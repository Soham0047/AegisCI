const assert = require("node:assert/strict");
const test = require("node:test");

const {
  MARKER,
  decideCommentAction,
  findMarkerCommentIndex,
  normalizeReportBody,
} = require("./comment_updater_dryrun");

test("decides create when no marker exists", () => {
  const result = decideCommentAction(["no marker here"], "report body");
  assert.equal(result.action, "create");
  assert.equal(result.index, null);
});

test("decides update when marker exists", () => {
  const result = decideCommentAction(
    ["first comment", `${MARKER}\nGuardian report`],
    "report body"
  );
  assert.equal(result.action, "update");
  assert.equal(result.index, 1);
});

test("updates the comment that includes the marker", () => {
  const index = findMarkerCommentIndex([
    "old comment",
    "another comment",
    `${MARKER}\nolder guardian report`,
  ]);
  assert.equal(index, 2);
});

test("deduplicates marker and keeps it at the top", () => {
  const report = `Line 1\n${MARKER}\nLine 2\n${MARKER}`;
  const normalized = normalizeReportBody(report);
  const markerCount = normalized.split(MARKER).length - 1;

  assert.equal(markerCount, 1);
  assert.equal(normalized.split(/\r?\n/)[0], MARKER);
});
