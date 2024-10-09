// Code generated by protoc-gen-ts_proto. DO NOT EDIT.
// versions:
//   protoc-gen-ts_proto  v2.2.1
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

export interface UsersServiceClient {
  signUp(request: SignUpMsg): Observable<UserIdMsg>;

  banUser(request: UserIdMsg): Observable<Empty>;

  unbanUser(request: UserIdMsg): Observable<Empty>;

  deleteUser(request: UserIdMsg): Observable<Empty>;
}

export interface UsersServiceController {
  signUp(request: SignUpMsg): Promise<UserIdMsg> | Observable<UserIdMsg> | UserIdMsg;

  banUser(request: UserIdMsg): Promise<Empty> | Observable<Empty> | Empty;

  unbanUser(request: UserIdMsg): Promise<Empty> | Observable<Empty> | Empty;

  deleteUser(request: UserIdMsg): Promise<Empty> | Observable<Empty> | Empty;
}

export function UsersServiceControllerMethods() {
  return function (constructor: Function) {
    const grpcMethods: string[] = ["signUp", "banUser", "unbanUser", "deleteUser"];
    for (const method of grpcMethods) {
      const descriptor: any = Reflect.getOwnPropertyDescriptor(constructor.prototype, method);
      GrpcMethod("UsersService", method)(constructor.prototype[method], method, descriptor);
    }
    const grpcStreamMethods: string[] = [];
    for (const method of grpcStreamMethods) {
      const descriptor: any = Reflect.getOwnPropertyDescriptor(constructor.prototype, method);
      GrpcStreamMethod("UsersService", method)(constructor.prototype[method], method, descriptor);
    }
  };
}

export const USERS_SERVICE_NAME = "UsersService";