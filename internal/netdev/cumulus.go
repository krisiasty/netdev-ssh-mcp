package netdev

// cumulusMergeStderr is appended to every command built for Cumulus Linux 4.x.
// NCLU's error stream is undocumented, so stderr is merged into stdout to make
// sure it reaches obfuscation. It is the only shell syntax the server adds.
const cumulusMergeStderr = " 2>&1"
