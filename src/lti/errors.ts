/**
 * Launch failures carry a machine-readable code for logs and metrics, while the message
 * shown to a user stays generic. A rejected launch must not tell an attacker which of the
 * checks failed.
 */
export type LaunchErrorCode =
  | 'missing_parameter'
  | 'unknown_platform'
  | 'unknown_state'
  | 'expired_state'
  | 'invalid_signature'
  | 'invalid_token'
  | 'token_expired'
  | 'audience_mismatch'
  | 'nonce_mismatch'
  | 'nonce_reused'
  | 'unknown_deployment'
  | 'unsupported_message_type'
  | 'unsupported_version'
  | 'target_link_mismatch'
  | 'missing_course_context';

export class LaunchError extends Error {
  override readonly name = 'LaunchError';

  constructor(
    readonly code: LaunchErrorCode,
    /** Detail for the operator's log. Never rendered to the user. */
    readonly detail?: string,
  ) {
    super(detail ? `${code}: ${detail}` : code);
  }
}

export function isLaunchError(error: unknown): error is LaunchError {
  return error instanceof LaunchError;
}
