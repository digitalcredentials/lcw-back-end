# Builds the webvh-verify layer for `sam build` (BuildMethod: makefile). The
# package is bundled with its dependencies into one ES module, the way the
# functions themselves are bundled, and placed where the Lambda Node.js
# runtime resolves a bare `import ... from "webvh-verify"`:
# /opt/nodejs/node_modules/webvh-verify.
build-WebvhVerifyLayer:
	npm ci --no-audit --no-fund
	npm run build
	mkdir -p "$(ARTIFACTS_DIR)/nodejs/node_modules/webvh-verify"
	cp dist/index.mjs "$(ARTIFACTS_DIR)/nodejs/node_modules/webvh-verify/index.mjs"
	printf '{ "name": "webvh-verify", "version": "1.0.0", "type": "module", "main": "index.mjs" }\n' > "$(ARTIFACTS_DIR)/nodejs/node_modules/webvh-verify/package.json"
