const fs = require("fs");

const MARKER = "<!-- SECUREDEV_GUARDIAN -->";

function normalizeReportBody(reportMarkdown) {
  const lines = (reportMarkdown || "").split(/\r?\n/);
  const filtered = lines.filter((line) => line.trim() !== MARKER);
  return [MARKER, ...filtered].join("\n");
}

function extractBody(comment) {
  if (typeof comment === "string") {
    return comment;
  }
  if (comment && typeof comment.body === "string") {
    return comment.body;
  }
  return "";
}

function findMarkerCommentIndex(comments) {
  for (let i = 0; i < comments.length; i += 1) {
    const body = extractBody(comments[i]);
    if (body.includes(MARKER)) {
      return i;
    }
  }
  return -1;
}

function decideCommentAction(comments, reportMarkdown) {
  const body = normalizeReportBody(reportMarkdown);
  const index = findMarkerCommentIndex(comments);
  return {
    action: index === -1 ? "create" : "update",
    index: index === -1 ? null : index,
    body,
  };
}

function getArgValue(flag) {
  const index = process.argv.indexOf(flag);
  if (index === -1) {
    return null;
  }
  return process.argv[index + 1] ?? null;
}

if (require.main === module) {
  const reportPath = getArgValue("--report");
  const commentsJson = getArgValue("--comments");

  if (!reportPath || !commentsJson) {
    console.log(
      "Usage: node scripts/comment_updater_dryrun.js --report report.md --comments '[\"a\",\"b\"]'"
    );
    process.exit(1);
  }

  const reportMarkdown = fs.readFileSync(reportPath, "utf8");
  const comments = JSON.parse(commentsJson);
  const result = decideCommentAction(comments, reportMarkdown);
  console.log(JSON.stringify(result, null, 2));
}

module.exports = {
  MARKER,
  normalizeReportBody,
  findMarkerCommentIndex,
  decideCommentAction,
};
