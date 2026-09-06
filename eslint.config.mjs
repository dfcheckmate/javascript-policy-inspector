import js from "@eslint/js";
import globals from "globals";
import json from "@eslint/json";
import css from "@eslint/css";
import { defineConfig } from "eslint/config";

export default defineConfig([
  {
    ignores: [
      "**/.yarn/**",
      "**/node_modules/**",

      // Yarn Plug'n'Play generated files
      ".pnp.cjs",
      ".pnp.loader.mjs",

      // Generated build output
      "dist-firefox/**",
      "dist-chrome/**",
      "build/**",
      "coverage/**",

      // Bundled files
      "**/*.bundled.js",
    ],
  },

  {
    files: ["**/*.{js,mjs,cjs}"],
    plugins: { js },
    extends: ["js/recommended"],
    languageOptions: {
      globals: {
        ...globals.browser,
        chrome: "readonly",
      },
    },
  },

  {
    // test-page harness: mark() is defined by mark.js on window
    files: ["test-page/**/*.js"],
    languageOptions: {
      globals: {
        mark: "readonly",
      },
    },
  },

  {
    files: ["**/*.json"],
    plugins: { json },
    language: "json/json",
    extends: ["json/recommended"],
  },

  {
    files: ["**/*.css"],
    plugins: { css },
    language: "css/css",
    extends: ["css/recommended"],
  },
]);
