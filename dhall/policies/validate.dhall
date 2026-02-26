-- Validation assertions for the composed policy.
-- Dhall evaluates these at type-check time; any assertion failure is a compile error.
let Grant = ./types/Grant.dhall
let policy = ./compose.dhall

-- Assert: at least one grant exists
let _ = assert : Natural/isZero (List/length Grant policy.grants) === False

-- Verify version is the expected value
let _ = assert : policy.version === "0.2.0"

in  policy
