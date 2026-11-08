const assert = require("node:assert");

const { formatMoney } = require("../src/lib/format");

assert.equal(formatMoney(12.5), "$12.50");
assert.equal(formatMoney(undefined), "$0.00");

console.log("order tests passed");
