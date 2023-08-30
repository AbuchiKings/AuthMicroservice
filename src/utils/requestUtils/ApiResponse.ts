import { Response } from 'express';

enum StatusCode {
  SUCCESS = 'success',
  FAILURE = 'error',
  RETRY = 'retry',
  INVALID_ACCESS_TOKEN = 'access_denied',
}

enum ResponseStatus {
  SUCCESS = 200,
  CREATED_SUCCESS= 201,
  BAD_REQUEST = 400,
  UNAUTHORIZED = 401,
  FORBIDDEN = 403,
  NOT_FOUND = 404,
  INTERNAL_ERROR = 500,
  CONFLICT= 409,
  UNPROCESSIBLE_ENTITY= 422,
  TOO_MANY_REQUESTS= 429,
}

abstract class ApiResponse {
  constructor(
    protected status: StatusCode,
    protected statusCode: ResponseStatus,
    protected message: string,
    protected results: number = 0,
  ) { }

  protected prepare<T extends ApiResponse>(res: Response, response: T): Response {
    return res.status(this.statusCode).json(ApiResponse.sanitize(response));
  }

  public send(res: Response): Response {
    return this.prepare<ApiResponse>(res, this);
  }

  private static sanitize<T extends ApiResponse>(response: T): T {
    const clone: T = {} as T;
    Object.assign(clone, response);
    // @ts-ignore
    delete clone.statusCode;
    for (const i in clone) if (typeof clone[i] === 'undefined') delete clone[i];
    return clone;
  }
}

export class AuthFailureResponse extends ApiResponse {
  constructor(message = 'Authentication Failure') {
    super(StatusCode.FAILURE, ResponseStatus.UNAUTHORIZED, message);
  }
}

export class NotFoundResponse extends ApiResponse {
  //private url: string | undefined;

  constructor(message = 'Not Found') {
    super(StatusCode.FAILURE, ResponseStatus.NOT_FOUND, message);
  }

  send(res: Response): Response {
    //this.url = res.req?.originalUrl;
    return super.prepare<NotFoundResponse>(res, this);
  }
}

export class ForbiddenResponse extends ApiResponse {
  constructor(message = 'Forbidden') {
    super(StatusCode.FAILURE, ResponseStatus.FORBIDDEN, message);
  }
}

export class BadRequestResponse extends ApiResponse {
  constructor(message = 'Bad Parameters') {
    super(StatusCode.FAILURE, ResponseStatus.BAD_REQUEST, message);
  }
}

export class InternalErrorResponse extends ApiResponse {
  constructor(message = 'Internal Error') {
    super(StatusCode.FAILURE, ResponseStatus.INTERNAL_ERROR, message);
  }
}

export class SuccessMsgResponse extends ApiResponse {
  constructor(message: string) {
    super(StatusCode.SUCCESS, ResponseStatus.SUCCESS, message);
  }
}

export class FailureMsgResponse extends ApiResponse {
  constructor(message: string) {
    super(StatusCode.FAILURE, ResponseStatus.SUCCESS, message);
  }
}

export class SuccessResponse<T> extends ApiResponse {
  constructor(message: string, private data: T, result: number) {
    super(StatusCode.SUCCESS, ResponseStatus.SUCCESS, message, result);
  }

  send(res: Response): Response {
    return super.prepare<SuccessResponse<T>>(res, this);
  }
}

export class CreatedSuccessResponse<T> extends ApiResponse {
  constructor(message: string, private data: T, result: number) {
    super(StatusCode.SUCCESS, ResponseStatus.CREATED_SUCCESS, message, result);
  }

  send(res: Response): Response {
    return super.prepare<CreatedSuccessResponse<T>>(res, this);
  }
}

export class AccessTokenErrorResponse extends ApiResponse {
  private instruction = 'refresh_token';

  constructor(message = 'Access token invalid') {
    super(StatusCode.INVALID_ACCESS_TOKEN, ResponseStatus.UNAUTHORIZED, message);
  }

  send(res: Response): Response {
    res.setHeader('instruction', this.instruction);
    return super.prepare<AccessTokenErrorResponse>(res, this);
  }
}

export class TokenRefreshResponse extends ApiResponse {
  constructor(message: string, private accessToken: string, private refreshToken: string) {
    super(StatusCode.SUCCESS, ResponseStatus.SUCCESS, message);
  }

  send(res: Response): Response {
    return super.prepare<TokenRefreshResponse>(res, this);
  }
}

export class ConflictMsgResponse extends ApiResponse {
  constructor(message= 'Conflict') {
      super(StatusCode.FAILURE, ResponseStatus.CONFLICT, message);
  }
}

export class UnprocessibleEntityResponse extends ApiResponse {
  constructor(message = 'Invalid Input') {
      super(StatusCode.FAILURE, ResponseStatus.UNPROCESSIBLE_ENTITY, message);
  }
}

