/**
 * Exit codes: 0 success, 1 user error, 2 network/server error.
 */
export type ExitCode = 1 | 2;

export class CliError extends Error {
  readonly exitCode: ExitCode;

  constructor(message: string, exitCode: ExitCode = 1) {
    super(message);
    this.name = "CliError";
    this.exitCode = exitCode;
  }
}

/** User error: bad input, bad URL, wrong password, gone secret. Exit 1. */
export function userError(message: string): CliError {
  return new CliError(message, 1);
}

/** Network/server error: 5xx, 429, connection failures. Exit 2. */
export function serverError(message: string): CliError {
  return new CliError(message, 2);
}
