import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["dist/**", "node_modules/**", "coverage/**"]
  },
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    files: ["**/*.ts"],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname
      }
    },
    rules: {
      "@typescript-eslint/consistent-type-definitions": ["error", "type"],
      "@typescript-eslint/no-confusing-void-expression": "off",
      "@typescript-eslint/no-magic-numbers": "off",
      "@typescript-eslint/no-non-null-assertion": "off",
      "@typescript-eslint/prefer-readonly-parameter-types": "off",
      "@typescript-eslint/restrict-template-expressions": [
        "error",
        {
          "allowNumber": true
        }
      ]
    }
  },
  {
    files: ["**/*.mjs"],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: {
      globals: {
        process: "readonly"
      }
    }
  },
  {
    files: ["test/host/**/*.cjs"],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: {
      globals: {
        module: "readonly",
        process: "readonly",
        require: "readonly"
      }
    },
    rules: {
      ...tseslint.configs.disableTypeChecked.rules,
      "@typescript-eslint/no-require-imports": "off"
    }
  }
);
