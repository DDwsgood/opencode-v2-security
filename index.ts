// Root entrypoint shim for loading this plugin as a local **directory** target.
// The host resolves a directory plugin through `<dir>/server` or `<dir>/index`
// (it does not consult package.json exports for directory targets), while the
// published npm package resolves `.` through package.json. Both paths land here.
export { default } from "./src/index"
