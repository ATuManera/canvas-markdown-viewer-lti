import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { LaunchError } from '../../src/lti/errors.ts';
import { InMemoryLaunchStateStore } from '../../src/lti/state-store.ts';
import { beginLogin } from '../../src/lti/login.ts';
import { validateLaunch } from '../../src/lti/validate.ts';
import {
  buildPlatform,
  buildRegistry,
  CLIENT_ID,
  COURSE_ID,
  createSigningKey,
  DEPLOYMENT_ID,
  ISSUER,
  launchClaims,
  TOOL_LAUNCH_URI,
  USER_ID,
  type SigningKey,
} from '../helpers/lti-fixtures.ts';

const REDIRECT_URI = TOOL_LAUNCH_URI;

let key: SigningKey;
let store: InMemoryLaunchStateStore;
const platform = buildPlatform();
const registry = buildRegistry(platform);

/** Returns the `state` plus the `nonce` the tool sent with it. */
async function login(): Promise<{ state: string; nonce: string }> {
  const result = await beginLogin(
    { iss: ISSUER, login_hint: 'user-1', client_id: CLIENT_ID, target_link_uri: TOOL_LAUNCH_URI },
    { registry, store, redirectUri: REDIRECT_URI },
  );
  const nonce = new URL(result.redirectUrl).searchParams.get('nonce');
  expect(nonce).toBeTruthy();
  return { state: result.state, nonce: nonce! };
}

async function expectRejection(promise: Promise<unknown>, code: string): Promise<LaunchError> {
  try {
    await promise;
    expect.unreachable(`expected rejection with code ${code}`);
  } catch (error) {
    expect(error).toBeInstanceOf(LaunchError);
    expect((error as LaunchError).code).toBe(code);
    return error as LaunchError;
  }
}

beforeAll(async () => {
  key = await createSigningKey();
});

beforeEach(() => {
  store = new InMemoryLaunchStateStore();
});

describe('beginLogin', () => {
  it('redirects to the platform authorization endpoint with the required parameters', async () => {
    const result = await beginLogin(
      { iss: ISSUER, login_hint: 'user-1', client_id: CLIENT_ID },
      { registry, store, redirectUri: REDIRECT_URI },
    );
    const url = new URL(result.redirectUrl);

    expect(url.origin + url.pathname).toBe(`${ISSUER}/api/lti/authorize_redirect`);
    expect(url.searchParams.get('scope')).toBe('openid');
    expect(url.searchParams.get('response_type')).toBe('id_token');
    expect(url.searchParams.get('response_mode')).toBe('form_post');
    expect(url.searchParams.get('prompt')).toBe('none');
    expect(url.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(url.searchParams.get('redirect_uri')).toBe(REDIRECT_URI);
    expect(url.searchParams.get('login_hint')).toBe('user-1');
    expect(url.searchParams.get('state')).toBe(result.state);
    expect(url.searchParams.get('nonce')).toBeTruthy();
  });

  it('mints a distinct state and nonce on every login', async () => {
    const a = await login();
    const b = await login();
    expect(a.state).not.toBe(b.state);
    expect(a.nonce).not.toBe(b.nonce);
  });

  it('rejects a login without iss', async () => {
    await expectRejection(
      beginLogin({ login_hint: 'u' }, { registry, store, redirectUri: REDIRECT_URI }),
      'missing_parameter',
    );
  });

  it('rejects a login without login_hint', async () => {
    await expectRejection(
      beginLogin({ iss: ISSUER }, { registry, store, redirectUri: REDIRECT_URI }),
      'missing_parameter',
    );
  });

  it('rejects an unregistered issuer', async () => {
    await expectRejection(
      beginLogin(
        { iss: 'https://evil.example', login_hint: 'u' },
        { registry, store, redirectUri: REDIRECT_URI },
      ),
      'unknown_platform',
    );
  });

  it('rejects a known issuer presenting another tool’s client_id', async () => {
    await expectRejection(
      beginLogin(
        { iss: ISSUER, login_hint: 'u', client_id: 'someone-elses-tool' },
        { registry, store, redirectUri: REDIRECT_URI },
      ),
      'unknown_platform',
    );
  });

  it('infers the platform when a single registration exists and client_id is absent', async () => {
    const result = await beginLogin(
      { iss: ISSUER, login_hint: 'u' },
      { registry, store, redirectUri: REDIRECT_URI },
    );
    expect(new URL(result.redirectUrl).searchParams.get('client_id')).toBe(CLIENT_ID);
  });

  it('refuses to guess when the issuer has several registrations and client_id is absent', async () => {
    const twoRegistrations = buildRegistry(platform, buildPlatform({ clientId: 'second-tool' }));
    await expectRejection(
      beginLogin(
        { iss: ISSUER, login_hint: 'u' },
        { registry: twoRegistrations, store, redirectUri: REDIRECT_URI },
      ),
      'unknown_platform',
    );
  });
});

describe('validateLaunch — a well-formed launch', () => {
  it('accepts it and extracts the launch context', async () => {
    const { state, nonce } = await login();
    const idToken = await key.sign(launchClaims({ nonce }));

    const result = await validateLaunch(
      { id_token: idToken, state },
      { registry, store, keyResolver: () => key.resolver },
    );

    expect(result.platform.issuer).toBe(ISSUER);
    expect(result.context.identity.deploymentId).toBe(DEPLOYMENT_ID);
    expect(result.context.identity.subject).toBe('lti-user-subject-1');
    expect(result.context.canvasCourseId).toBe(COURSE_ID);
    expect(result.context.canvasUserId).toBe(USER_ID);
    expect(result.context.canvasApiDomain).toBe('canvas.test.edu');
    expect(result.context.contextTitle).toBe('Curso de prueba');
    expect(result.context.locale).toBe('es');
    expect(result.context.roles).toContain(
      'http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor',
    );
  });

  it('accepts an azp that identifies this tool', async () => {
    const { state, nonce } = await login();
    const idToken = await key.sign(launchClaims({ nonce, azp: CLIENT_ID }));
    await expect(
      validateLaunch(
        { id_token: idToken, state },
        { registry, store, keyResolver: () => key.resolver },
      ),
    ).resolves.toBeDefined();
  });
});

describe('validateLaunch — missing parameters', () => {
  it('rejects a callback with no state', async () => {
    const { nonce } = await login();
    const idToken = await key.sign(launchClaims({ nonce }));
    await expectRejection(
      validateLaunch({ id_token: idToken }, { registry, store, keyResolver: () => key.resolver }),
      'missing_parameter',
    );
  });

  it('rejects a callback with no id_token', async () => {
    const { state } = await login();
    await expectRejection(
      validateLaunch({ state }, { registry, store, keyResolver: () => key.resolver }),
      'missing_parameter',
    );
  });
});

describe('validateLaunch — replay and state binding', () => {
  it('rejects a second use of the same state', async () => {
    const { state, nonce } = await login();
    const idToken = await key.sign(launchClaims({ nonce }));
    const options = { registry, store, keyResolver: () => key.resolver };

    await expect(validateLaunch({ id_token: idToken, state }, options)).resolves.toBeDefined();
    await expectRejection(validateLaunch({ id_token: idToken, state }, options), 'unknown_state');
  });

  it('rejects a state that was never issued', async () => {
    const { nonce } = await login();
    const idToken = await key.sign(launchClaims({ nonce }));
    await expectRejection(
      validateLaunch(
        { id_token: idToken, state: 'fabricated-state' },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'unknown_state',
    );
  });

  it('rejects an expired state', async () => {
    const result = await beginLogin(
      { iss: ISSUER, login_hint: 'u', client_id: CLIENT_ID },
      { registry, store, redirectUri: REDIRECT_URI, stateTtlMs: -1 },
    );
    const nonce = new URL(result.redirectUrl).searchParams.get('nonce')!;
    const idToken = await key.sign(launchClaims({ nonce }));
    await expectRejection(
      validateLaunch(
        { id_token: idToken, state: result.state },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'unknown_state',
    );
  });

  it('rejects a token whose nonce belongs to a different login attempt', async () => {
    const first = await login();
    const second = await login();
    const idToken = await key.sign(launchClaims({ nonce: first.nonce }));

    await expectRejection(
      validateLaunch(
        { id_token: idToken, state: second.state },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'nonce_mismatch',
    );
  });

  it('rejects a token with no nonce at all', async () => {
    const { state, nonce } = await login();
    const claims = launchClaims({ nonce });
    delete claims['nonce'];
    const idToken = await key.sign(claims);

    await expectRejection(
      validateLaunch(
        { id_token: idToken, state },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'nonce_mismatch',
    );
  });

  it('remembers a consumed nonce, so a captured token cannot be paired with a fresh state', async () => {
    const first = await login();
    const idToken = await key.sign(launchClaims({ nonce: first.nonce }));
    const options = { registry, store, keyResolver: () => key.resolver };

    await expect(
      validateLaunch({ id_token: idToken, state: first.state }, options),
    ).resolves.toBeDefined();

    // An attacker mints a new state through the normal login endpoint, then rewrites the
    // stored record's nonce to the captured one. The nonce memory is the last line here.
    const second = await login();
    await store.create({
      state: second.state,
      nonce: first.nonce,
      issuer: ISSUER,
      clientId: CLIENT_ID,
      targetLinkUri: TOOL_LAUNCH_URI,
      expiresAt: new Date(Date.now() + 60_000),
    });

    await expectRejection(
      validateLaunch({ id_token: idToken, state: second.state }, options),
      'nonce_reused',
    );
  });
});

describe('validateLaunch — cryptographic checks', () => {
  it('rejects a token signed by a key the platform does not publish', async () => {
    const attackerKey = await createSigningKey('attacker-key');
    const { state, nonce } = await login();
    const idToken = await attackerKey.sign(launchClaims({ nonce }), { kid: key.kid });

    await expectRejection(
      validateLaunch(
        { id_token: idToken, state },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'invalid_signature',
    );
  });

  it('rejects a tampered payload', async () => {
    const { state, nonce } = await login();
    const idToken = await key.sign(launchClaims({ nonce }));
    const [header, payload, signature] = idToken.split('.');
    const decoded = JSON.parse(Buffer.from(payload!, 'base64url').toString()) as Record<
      string,
      unknown
    >;
    decoded['sub'] = 'somebody-else';
    const forged = `${header}.${Buffer.from(JSON.stringify(decoded)).toString('base64url')}.${signature}`;

    await expectRejection(
      validateLaunch(
        { id_token: forged, state },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'invalid_signature',
    );
  });

  it('rejects an unsigned (alg=none) token', async () => {
    const { state, nonce } = await login();
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify(launchClaims({ nonce }))).toString('base64url');

    await expectRejection(
      validateLaunch(
        { id_token: `${header}.${payload}.`, state },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'invalid_token',
    );
  });

  it('rejects an expired token', async () => {
    const { state, nonce } = await login();
    const past = Math.floor(Date.now() / 1000) - 3600;
    const idToken = await key.sign(launchClaims({ nonce, issuedAt: past - 60, expiresAt: past }));

    await expectRejection(
      validateLaunch(
        { id_token: idToken, state },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'token_expired',
    );
  });

  it('rejects a token whose audience is another tool', async () => {
    const { state, nonce } = await login();
    const idToken = await key.sign(launchClaims({ nonce, audience: 'someone-elses-tool' }));

    await expectRejection(
      validateLaunch(
        { id_token: idToken, state },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'audience_mismatch',
    );
  });

  it('rejects a token whose issuer differs from the registered platform', async () => {
    const { state, nonce } = await login();
    const idToken = await key.sign(launchClaims({ nonce, issuer: 'https://evil.example' }));

    await expectRejection(
      validateLaunch(
        { id_token: idToken, state },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'audience_mismatch',
    );
  });

  it('rejects a multi-valued audience without azp', async () => {
    const { state, nonce } = await login();
    const idToken = await key.sign(launchClaims({ nonce, audience: [CLIENT_ID, 'another-tool'] }));

    await expectRejection(
      validateLaunch(
        { id_token: idToken, state },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'audience_mismatch',
    );
  });

  it('rejects an azp naming a different tool', async () => {
    const { state, nonce } = await login();
    const idToken = await key.sign(
      launchClaims({ nonce, audience: [CLIENT_ID, 'another-tool'], azp: 'another-tool' }),
    );

    await expectRejection(
      validateLaunch(
        { id_token: idToken, state },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'audience_mismatch',
    );
  });

  it('does not accept a key set belonging to a different platform', async () => {
    const otherKey = await createSigningKey('other-platform-key');
    const { state, nonce } = await login();
    const idToken = await otherKey.sign(launchClaims({ nonce }));

    await expectRejection(
      validateLaunch(
        { id_token: idToken, state },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'invalid_signature',
    );
  });
});

describe('validateLaunch — LTI claim checks', () => {
  it('rejects an unregistered deployment id', async () => {
    const { state, nonce } = await login();
    const idToken = await key.sign(launchClaims({ nonce, deploymentId: '9:somewhere-else' }));

    await expectRejection(
      validateLaunch(
        { id_token: idToken, state },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'unknown_deployment',
    );
  });

  it('rejects a missing deployment id', async () => {
    const { state, nonce } = await login();
    const claims = launchClaims({ nonce });
    delete claims['https://purl.imsglobal.org/spec/lti/claim/deployment_id'];
    const idToken = await key.sign(claims);

    await expectRejection(
      validateLaunch(
        { id_token: idToken, state },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'unknown_deployment',
    );
  });

  it('rejects a deep linking request, which file_menu never produces', async () => {
    const { state, nonce } = await login();
    const idToken = await key.sign(launchClaims({ nonce, messageType: 'LtiDeepLinkingRequest' }));

    await expectRejection(
      validateLaunch(
        { id_token: idToken, state },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'unsupported_message_type',
    );
  });

  it('rejects an unexpected LTI version', async () => {
    const { state, nonce } = await login();
    const idToken = await key.sign(launchClaims({ nonce, version: '1.1.0' }));

    await expectRejection(
      validateLaunch(
        { id_token: idToken, state },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'unsupported_version',
    );
  });

  it('rejects a token with no subject', async () => {
    const { state, nonce } = await login();
    const claims = launchClaims({ nonce });
    delete claims['sub'];
    const idToken = await key.sign(claims);

    await expectRejection(
      validateLaunch(
        { id_token: idToken, state },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'invalid_token',
    );
  });
});

describe('validateLaunch — Canvas variable substitution', () => {
  it('treats an unexpanded substitution as absent', async () => {
    const { state, nonce } = await login();
    const idToken = await key.sign(launchClaims({ nonce, courseId: '$Canvas.course.id' }));

    const result = await validateLaunch(
      { id_token: idToken, state },
      { registry, store, keyResolver: () => key.resolver },
    );
    expect(result.context.canvasCourseId).toBeUndefined();
  });

  it('refuses a non-numeric course id rather than passing it to the Canvas API', async () => {
    const { state, nonce } = await login();
    const idToken = await key.sign(launchClaims({ nonce, courseId: '../../accounts/1' }));

    const result = await validateLaunch(
      { id_token: idToken, state },
      { registry, store, keyResolver: () => key.resolver },
    );
    expect(result.context.canvasCourseId).toBeUndefined();
  });

  it('reports an absent course claim as undefined', async () => {
    const { state, nonce } = await login();
    const idToken = await key.sign(launchClaims({ nonce, courseId: null }));

    const result = await validateLaunch(
      { id_token: idToken, state },
      { registry, store, keyResolver: () => key.resolver },
    );
    expect(result.context.canvasCourseId).toBeUndefined();
  });
});

describe('error messages', () => {
  it('never reveal which internal check failed in the user-facing code', async () => {
    const { state, nonce } = await login();
    const idToken = await key.sign(launchClaims({ nonce, deploymentId: 'nope' }));
    const error = await expectRejection(
      validateLaunch(
        { id_token: idToken, state },
        { registry, store, keyResolver: () => key.resolver },
      ),
      'unknown_deployment',
    );
    // The detail exists for the operator's log, and is deliberately separate from the code.
    expect(error.detail).toBeDefined();
    expect(error.code).not.toContain(' ');
  });
});

describe('beginLogin — Platform Storage', () => {
  it('reports the frame Canvas named, so the relay page can address it', async () => {
    const result = await beginLogin(
      {
        iss: ISSUER,
        login_hint: 'u',
        client_id: CLIENT_ID,
        lti_storage_target: 'post_message_forwarding',
      },
      { registry, store, redirectUri: REDIRECT_URI },
    );

    expect(result.storageTarget).toBe('post_message_forwarding');
  });

  it('reports no target when Canvas does not offer Platform Storage', async () => {
    const result = await beginLogin(
      { iss: ISSUER, login_hint: 'u', client_id: CLIENT_ID },
      { registry, store, redirectUri: REDIRECT_URI },
    );

    expect(result.storageTarget).toBeUndefined();
  });

  it('accepts the specification default of _parent', async () => {
    const result = await beginLogin(
      { iss: ISSUER, login_hint: 'u', client_id: CLIENT_ID, lti_storage_target: '_parent' },
      { registry, store, redirectUri: REDIRECT_URI },
    );

    expect(result.storageTarget).toBe('_parent');
  });

  it('reports the authorization origin, which may differ from the issuer host', async () => {
    const hosted = buildPlatform({
      clientId: 'hosted-tool',
      authorizationEndpoint: 'https://sso.canvaslms.com/api/lti/authorize_redirect',
    });
    const result = await beginLogin(
      { iss: ISSUER, login_hint: 'u', client_id: 'hosted-tool' },
      { registry: buildRegistry(platform, hosted), store, redirectUri: REDIRECT_URI },
    );

    expect(result.authorizationOrigin).toBe('https://sso.canvaslms.com');
  });
});
