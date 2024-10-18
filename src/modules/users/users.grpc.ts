// Code generated by protoc-gen-ts_proto. DO NOT EDIT.
// versions:
//   protoc-gen-ts_proto  v2.2.4
//   protoc               v3.20.3
// source: modules/users/users.grpc.proto

/* eslint-disable */
import { GrpcMethod, GrpcStreamMethod } from "@nestjs/microservices";
import { Observable } from "rxjs";

export const protobufPackage = "users";

export interface Empty {
}

export interface SignUpMsg {
  username: string;
  email: string;
}

export interface UserIdMsg {
  userId: string;
}

export const USERS_PACKAGE_NAME = "users";

export interface UserServiceClient {
  signUp(request: SignUpMsg): Observable<UserIdMsg>;

  banUser(request: UserIdMsg): Observable<Empty>;

  unbanUser(request: UserIdMsg): Observable<Empty>;

  deleteUser(request: UserIdMsg): Observable<Empty>;
}

export interface UserServiceController {
  signUp(request: SignUpMsg): Promise<UserIdMsg> | Observable<UserIdMsg> | UserIdMsg;

  banUser(request: UserIdMsg): Promise<Empty> | Observable<Empty> | Empty;

  unbanUser(request: UserIdMsg): Promise<Empty> | Observable<Empty> | Empty;

  deleteUser(request: UserIdMsg): Promise<Empty> | Observable<Empty> | Empty;
}

export function UserServiceControllerMethods() {
  return function (constructor: Function) {
    const grpcMethods: string[] = ["signUp", "banUser", "unbanUser", "deleteUser"];
    for (const method of grpcMethods) {
      const descriptor: any = Reflect.getOwnPropertyDescriptor(constructor.prototype, method);
      GrpcMethod("UserService", method)(constructor.prototype[method], method, descriptor);
    }
    const grpcStreamMethods: string[] = [];
    for (const method of grpcStreamMethods) {
      const descriptor: any = Reflect.getOwnPropertyDescriptor(constructor.prototype, method);
      GrpcStreamMethod("UserService", method)(constructor.prototype[method], method, descriptor);
    }
  };
}

export const USER_SERVICE_NAME = "UserService";
