const TAG_REGEX = /<[^>]*>/g;

const stripControlCharacters = (value: string): string => {
  let sanitized = "";
  for (const char of value) {
    const code = char.charCodeAt(0);
    if (code >= 0x20 && code !== 0x7f) {
      sanitized += char;
    }
  }
  return sanitized;
};

export interface SanitizeOptions {
  maxLength?: number;
  allowNewLines?: boolean;
  trim?: boolean;
}

export function sanitizeInput(value: string, options?: SanitizeOptions): string {
  if (!value) return "";

  const { maxLength, allowNewLines = false, trim = true } = options || {};

  let safeValue = value.replace(TAG_REGEX, "");
  safeValue = safeValue.replace(/[<>]/g, "");
  safeValue = stripControlCharacters(safeValue);

  if (!allowNewLines) {
    safeValue = safeValue.replace(/[\r\n]+/g, " ");
  }

  if (trim) {
    safeValue = safeValue.trim();
  }

  if (maxLength && maxLength > 0) {
    safeValue = safeValue.slice(0, maxLength);
  }

  return safeValue;
}

export function containsXssRisk(value: string): boolean {
  if (!value) return false;
  const lowered = value.toLowerCase();
  return /<\s*script|javascript:|onerror\s*=|onload\s*=|data:text\/html|<iframe|<object/.test(lowered);
}

export function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export function isStrongPassword(password: string): boolean {
  return password.length >= 8 && /[A-Za-z]/.test(password) && /[0-9]/.test(password);
}

export function isValidUsername(username: string): boolean {
  return /^[A-Za-z0-9._-]{3,32}$/.test(username);
}

export function isValidName(name: string): boolean {
  return /^[A-Za-z'\-\s]{2,60}$/.test(name);
}
