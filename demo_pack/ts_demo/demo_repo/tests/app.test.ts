import { formatDate, sanitizeInput } from '../src/app';

describe('app utilities', () => {
  describe('formatDate', () => {
    it('should format date as YYYY-MM-DD', () => {
      const date = new Date('2024-06-15T12:00:00Z');
      expect(formatDate(date)).toBe('2024-06-15');
    });
  });

  describe('sanitizeInput', () => {
    it('should remove dangerous characters', () => {
      expect(sanitizeInput('<script>alert("xss")</script>')).toBe('scriptalert(xss)/script');
    });

    it('should handle normal input', () => {
      expect(sanitizeInput('Hello World')).toBe('Hello World');
    });
  });
});
