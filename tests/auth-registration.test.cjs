const assert = require("node:assert/strict");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const validatorsPath = path.resolve(__dirname, "../src/lib/validators.ts");
const source = fs.readFileSync(validatorsPath, "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2022,
  },
}).outputText;
const validatorsModule = new Module(validatorsPath, module);
validatorsModule.filename = validatorsPath;
validatorsModule.paths = Module._nodeModulePaths(path.dirname(validatorsPath));
validatorsModule._compile(compiled, validatorsPath);

const { RegisterSchema } = validatorsModule.exports;
const validRegistration = {
  email: "alicia@example.test",
  password: "Abcdef1!",
};

test("registration requires a non-empty name and trims valid names", () => {
  assert.equal(RegisterSchema.safeParse(validRegistration).success, false);
  assert.equal(
    RegisterSchema.safeParse({ ...validRegistration, name: "   " }).success,
    false,
  );
  assert.deepEqual(
    RegisterSchema.parse({ ...validRegistration, name: "  Alicia  " }),
    { ...validRegistration, email: "alicia@example.test", name: "Alicia" },
  );
});
