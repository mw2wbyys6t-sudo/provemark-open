const path = require("node:path");

module.exports = {
  entry: "./src/index.js",
  output: {
    filename: "bundle.js",
    path: path.resolve(__dirname, "dist"),
  },
  module: {
    rules: [{ test: /\.jsx?$/, exclude: /node_modules/, use: "babel-loader" }],
  },
  resolve: { extensions: [".js", ".jsx"] },
  devtool: "source-map",
};
