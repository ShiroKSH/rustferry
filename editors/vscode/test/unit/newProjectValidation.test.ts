import { describe, expect, it } from "vitest";

import {
  deriveDefaultIdentifier,
  validateIdentifier,
  validateProjectName
} from "../../src/commands/newProjectValidation.js";

describe("new-project validation", () => {
  it("matches the Rust CLI cross-platform project-name rules", () => {
    expect(validateProjectName("Weather App")).toBeUndefined();
    expect(validateProjectName("Погода")).toBeUndefined();
    expect(validateProjectName("NUL")).toContain("Windows");
    expect(validateProjectName("con.notes")).toContain("Windows");
    expect(validateProjectName("../weather")).toContain("separators");
    expect(validateProjectName("weather?")).toContain("unsafe");
  });

  it("accepts only the portable lowercase identifier intersection", () => {
    expect(validateIdentifier("com.example.weather")).toBeUndefined();
    expect(validateIdentifier("com.Example.weather")).toContain("lowercase");
    expect(validateIdentifier("com.example.weather_app")).toContain("lowercase");
    expect(validateIdentifier("example")).toContain("three");
    expect(validateIdentifier(`com.example.${"a".repeat(244)}`)).toContain("255");
  });

  it("derives the same registry-safe default shape as the Rust CLI", () => {
    expect(deriveDefaultIdentifier("my_app")).toBe("org.rustferry.myapp");
    expect(deriveDefaultIdentifier("fn")).toBe("org.rustferry.appfn");
    expect(deriveDefaultIdentifier("9 Lives")).toBe("org.rustferry.app9lives");
    expect(deriveDefaultIdentifier("Погода")).toMatch(/^org\.rustferry\.app[0-9a-f]{8}$/u);
  });
});
