// Root entrypoint shim so a plugin configured as a local **directory** resolves
// its TUI companion at `<dir>/tui` (Host.resolve probes the bare "tui" subpath
// for directory targets and cannot see the package `exports["./tui"]`).
// The published npm package resolves `./tui` through package.json exports instead.
export { default } from "./src/tui"
