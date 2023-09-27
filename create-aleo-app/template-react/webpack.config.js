import CopyPlugin from "copy-webpack-plugin";

import HtmlWebpackPlugin from "html-webpack-plugin";

import path from "path";

const appConfig = {
  mode: "production",
  entry: {
    index: "./src/main.jsx",
  },
  output: {
    path: path.resolve("dist"),
    filename: "[name].bundle.js",
  },
  resolve: {
    extensions: [".js", ".wasm", ".jsx"],
  },
  devServer: {
    port: 3000,
    headers: {
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
    },
    client: {
      overlay: false,
    },
  },
  module: {
    rules: [
      {
        test: /\.(js|jsx)$/,
        exclude: /nodeModules/,
        use: {
          loader: "babel-loader",
        },
      },
      {
        test: /\.css$/,
        use: ["style-loader", "css-loader"],
      },
      {
        test: /\.(png|jpe?g|gif)$/i,
        use: [
          {
            loader: "file-loader",
            options: {
              name: "[path][name].[ext]",
            },
          },
        ],
      },
      {
        test: /\.svg$/,
        use: [
          {
            loader: "svg-url-loader",
            options: {
              limit: 8192,
              noquotes: true,
            },
          },
        ],
      },
    ],
  },
  plugins: [
    new CopyPlugin({
      patterns: [{ from: "public", to: "public" }],
    }),
    new HtmlWebpackPlugin({
      template: "./index.html",
    }),
  ],
  performance: {
    hints: false,
    maxAssetSize: 13 * 1024 * 1024, // 12 MiB
    maxEntrypointSize: 13 * 1024 * 1024, // 12 MiB
  },
  stats: {
    warnings: false,
  },
  experiments: {
    asyncWebAssembly: true,
    topLevelAwait: true,
  },
  devtool: "source-map",
};

export default [appConfig];
