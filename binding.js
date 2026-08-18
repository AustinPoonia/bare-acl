// Separated from index.js for the reason every bare addon does it: `require.addon`
// resolves against the file that calls it, so keeping it in its own module means
// index.js can be bundled or moved without the addon lookup following it.
module.exports = require.addon('.')
