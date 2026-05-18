// Client — should trigger the cross-lang chain back to the server's SQL inj.
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

const userService = new UserServiceClient('localhost:50051', grpc.credentials.createInsecure());

async function fetchUser(id) {
  return new Promise((resolve, reject) => {
    userService.GetUser({ id }, (err, resp) => err ? reject(err) : resolve(resp));
  });
}
