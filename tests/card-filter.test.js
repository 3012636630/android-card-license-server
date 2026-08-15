const assert = require("node:assert/strict");
const test = require("node:test");

const { deleteCardsByName, filterCardsByName } = require("../server");

const cards = [
  { cardKey: "A", cardName: "alpha" },
  { cardKey: "B", cardName: "beta" },
  { cardKey: "C", cardName: "ALPHA" }
];

test("filters cards by normalized exact card name", () => {
  assert.deepEqual(filterCardsByName(cards, " Alpha ").map((card) => card.cardKey), ["A", "C"]);
  assert.equal(filterCardsByName(cards, "").length, 3);
});

test("bulk delete removes only the filtered card name", () => {
  const result = deleteCardsByName(cards, "alpha");
  assert.equal(result.deleted, 2);
  assert.deepEqual(result.kept.map((card) => card.cardKey), ["B"]);
});

test("bulk delete with an empty filter removes all cards", () => {
  const result = deleteCardsByName(cards, "");
  assert.equal(result.deleted, 3);
  assert.deepEqual(result.kept, []);
});
