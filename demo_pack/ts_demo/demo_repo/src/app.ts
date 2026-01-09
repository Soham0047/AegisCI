/**
 * Demo TypeScript application with security vulnerabilities.
 *
 * Contains:
 * - innerHTML XSS vulnerability
 * - eval() code injection vulnerability
 */

/**
 * Render a message into an HTML element.
 * VULNERABLE: Uses innerHTML which allows XSS attacks.
 */
export function renderMessage(element: HTMLElement, message: string): void {
  element.innerHTML = message;
}

/**
 * Parse a JSON configuration string.
 * VULNERABLE: Uses eval() which allows code injection.
 */
export function parseConfig(jsonString: string): unknown {
  return eval(jsonString);
}

/**
 * Safe utility function (no vulnerability).
 */
export function formatDate(date: Date): string {
  return date.toISOString().split('T')[0];
}

/**
 * Another safe utility function.
 */
export function sanitizeInput(input: string): string {
  return input.replace(/[<>&"']/g, '');
}
