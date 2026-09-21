/**
 * LTI 1.3 claim identifiers.
 *
 * Source: 1EdTech Learning Tools Interoperability Core Specification 1.3,
 * https://www.imsglobal.org/spec/lti/v1p3/ (§4 Message claims).
 *
 * The Canvas-specific custom fields are the variable substitutions declared in the tool
 * configuration; see `config/canvas-lti.example.json`. Canvas documents them in
 * `doc/api/tools_variable_substitutions.md`.
 */

export const CLAIM = {
  messageType: 'https://purl.imsglobal.org/spec/lti/claim/message_type',
  version: 'https://purl.imsglobal.org/spec/lti/claim/version',
  deploymentId: 'https://purl.imsglobal.org/spec/lti/claim/deployment_id',
  targetLinkUri: 'https://purl.imsglobal.org/spec/lti/claim/target_link_uri',
  resourceLink: 'https://purl.imsglobal.org/spec/lti/claim/resource_link',
  roles: 'https://purl.imsglobal.org/spec/lti/claim/roles',
  context: 'https://purl.imsglobal.org/spec/lti/claim/context',
  custom: 'https://purl.imsglobal.org/spec/lti/claim/custom',
  launchPresentation: 'https://purl.imsglobal.org/spec/lti/claim/launch_presentation',
  toolPlatform: 'https://purl.imsglobal.org/spec/lti/claim/tool_platform',
} as const;

/** The only message type this tool accepts. Canvas allows no other for `file_menu`. */
export const RESOURCE_LINK_REQUEST = 'LtiResourceLinkRequest';

export const LTI_VERSION = '1.3.0';

/**
 * Names of the custom fields the tool configuration asks Canvas to substitute.
 * Canvas lowercases custom field keys and replaces `.` with `_` when it builds the claim.
 */
export const CUSTOM_FIELD = {
  courseId: 'canvas_course_id',
  userId: 'canvas_user_id',
  apiDomain: 'canvas_api_domain',
} as const;

export interface LaunchIdentity {
  /** The platform's `iss`, matched exactly against configuration. */
  readonly issuer: string;
  /** The LTI developer key client id this launch was issued for. */
  readonly clientId: string;
  readonly deploymentId: string;
  /** The platform's stable, pseudonymous identifier for the user (`sub`). */
  readonly subject: string;
}

export interface LaunchContext {
  readonly identity: LaunchIdentity;
  /** Canvas numeric course id, from `$Canvas.course.id`. Absent outside a course. */
  readonly canvasCourseId: string | undefined;
  /** Canvas numeric user id, from `$Canvas.user.id`. */
  readonly canvasUserId: string | undefined;
  /** Canvas API domain, from `$Canvas.api.domain`. */
  readonly canvasApiDomain: string | undefined;
  /** LTI context (course) title, for display only. */
  readonly contextTitle: string | undefined;
  readonly roles: readonly string[];
  /** BCP-47 tag from `launch_presentation`, used to pick the interface language. */
  readonly locale: string | undefined;
  readonly targetLinkUri: string;
}

/**
 * Canvas leaves a variable substitution as its literal `$Name` when it cannot expand it —
 * for instance `$Canvas.course.id` outside a course. Such a value means "absent", not "the
 * course is literally called $Canvas.course.id".
 */
export function expandedOrUndefined(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (trimmed === '' || trimmed.startsWith('$')) return undefined;
  return trimmed;
}

/** Canvas ids are numeric strings. Anything else is refused rather than passed to the API. */
export function asCanvasId(value: unknown): string | undefined {
  const expanded = expandedOrUndefined(value);
  if (expanded === undefined) return undefined;
  return /^[0-9]+$/.test(expanded) ? expanded : undefined;
}
