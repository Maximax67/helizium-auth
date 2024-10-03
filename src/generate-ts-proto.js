/* eslint-disable @typescript-eslint/no-var-requires */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execSync } = require('child_process');

const pluginPath =
  os.platform() === 'win32'
    ? '.\\node_modules\\.bin\\protoc-gen-ts_proto.cmd'
    : './node_modules/.bin/protoc-gen-ts_proto';

const absolutePath = path.resolve(__dirname);

function findProtoFiles(dir) {
  let protoFiles = [];
  const items = fs.readdirSync(dir);

  items.forEach((item) => {
    const fullPath = path.join(dir, item);
    const stat = fs.statSync(fullPath);

    if (stat.isDirectory()) {
      protoFiles = protoFiles.concat(findProtoFiles(fullPath));
    } else if (stat.isFile() && path.extname(item) === '.proto') {
      protoFiles.push(fullPath);
    }
  });
  return protoFiles;
}

function generateTsProto(filePath) {
  const command = `npx protoc --plugin=protoc-gen-ts_proto="${pluginPath}" --proto_path=${absolutePath} --ts_proto_opt=nestJs=true --ts_proto_out=src ${filePath}`;
  console.log('Building .proto: ' + filePath);
  execSync(command, { stdio: 'inherit' });
}

findProtoFiles(absolutePath).forEach(generateTsProto);
