#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import re
import uuid
from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from dataclasses import dataclass
from scoring import *

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


@dataclass
class CharField(object):
    required: bool
    nullable: bool


class ArgumentsField(CharField):
    pass


class EmailField(CharField):
    pass


class PhoneField(CharField):
    pass


class DateField(CharField):
    pass


class BirthDayField(CharField):
    pass


class GenderField(CharField):
    pass


class ClientIDsField(CharField):
    pass


class RequestFieldsParser(object):
    def __init__(self, args):
        for key, value in self.__dict__.items():
            self.__dict__[key] = args.setdefault(key, None)

    def get_filled_fields(self) -> list:
        fields = []
        for key, value in self.__dict__.items():
            if value is not None:
                fields.append(key)
        return fields[:]


class ClientsInterestsRequest(RequestFieldsParser, object):

    def __init__(self, args):
        self.client_ids = ClientIDsField(required=True, nullable=True)
        self.date = DateField(required=False, nullable=True)
        super().__init__(args=args)


class OnlineScoreRequest(RequestFieldsParser, object):

    def __init__(self, args):
        self.first_name = CharField(required=False, nullable=True)
        self.last_name = CharField(required=False, nullable=True)
        self.email = EmailField(required=False, nullable=True)
        self.phone = PhoneField(required=False, nullable=True)
        self.birthday = BirthDayField(required=False, nullable=True)
        self.gender = GenderField(required=False, nullable=True)
        super().__init__(args=args)

    @property
    def is_valid(self):
        pass
        return True


class MethodRequest(RequestFieldsParser, object):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, args):
        self.account = ''
        self.login = ''
        self.token = ''
        self.arguments = {}
        self.method = ''
        super().__init__(args=args)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


class RequestChecker(object):

    def __init__(self, request):
        self.request = request
        try:
            self.methodRequest = MethodRequest(args=dict(self.request.get("body")))
        except Exception as e:
            self.methodRequest = MethodRequest(args={})

    def logging_check(self, response, code):
        if code != OK:
            logging.error("%s: %s" % (ERRORS.get(code), response))

    def check_required_fields(self):
        req_list = self.methodRequest.get_filled_fields()
        for key, value in MethodRequest.__dict__.items():
            if hasattr(value, "required") is False:
                continue
            if value.required and key not in req_list:
                return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

        return '', OK

    def check_online_scoring(self):

        response, code = self.check_score_request()
        if code != OK:
            return response, code

        return '', OK

    def check_clients_interests(self):
        request = self.request.get("body")
        fields = ClientsInterestsRequest(request.get("arguments"))

        if (fields.client_ids is None or not fields.client_ids) or type(fields.client_ids) != list:
            return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

        if all(type(i) == int for i in fields.client_ids) is False:
            return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

        if fields.date is not None:
            try:
                date_valid = bool(datetime.datetime.strptime(str(fields.date), "%d.%m.%Y"))
            except ValueError:
                date_valid = False

            if not date_valid:
                return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

        return '', OK

    def check_empty_request(self):
        try:
            if not bool(self.request.get("body")):
                return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST
        except Exception as e:
            return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST
        return '', OK

    def check_auth(self):
        if not check_auth(self.methodRequest):
            return ERRORS.get(FORBIDDEN), FORBIDDEN
        return '', OK

    def check_method_request(self):
        if not self.request.get("body").get("method") in ["online_score", "clients_interests"]:
            return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST
        return '', OK

    def check_score_request(self):
        request = self.request.get("body")

        fields_dc: OnlineScoreRequest = request.get("arguments")
        if fields_dc is None or bool(fields_dc) is False:
            return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

        fields = OnlineScoreRequest(dict(request.get("arguments")))

        count_inconsistency = 0

        if fields.phone is None or fields.email is None:
            count_inconsistency += 1
        if fields.first_name is None or fields.last_name is None:
            count_inconsistency += 1
        if fields.gender is None or fields.birthday is None:
            count_inconsistency += 1

        if count_inconsistency == 3:
            return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

        if not str(fields.first_name).isalpha() or not str(fields.last_name).isalpha():
            return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

        if (len(str(fields.phone)) != 11 or int(str(fields.phone)[0]) != 7) and fields.phone is not None:
            return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if fields.email is not None and not re.match(pattern, str(fields.email)):
            return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

        if fields.gender not in [0, 1, 2] and fields.gender is not None:
            return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

        if fields.birthday is not None:

            try:
                birth_date = datetime.datetime.strptime(str(fields.birthday), "%d.%m.%Y")
                if datetime.datetime.today().year - birth_date.year >= 70:
                    return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST
                date_valid = bool(birth_date)
            except ValueError:
                date_valid = False

            if not date_valid:
                return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

        return '', OK


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode('utf-8')).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode('utf-8')).hexdigest()
    return digest == request.token


def method_handler(request, ctx, store):
    checker = RequestChecker(request)

    response, code = checker.check_empty_request()
    if code != OK:
        return response, code

    response, code = checker.check_required_fields()
    if code != OK:
        return response, code

    response, code = checker.check_auth()
    if code != OK:
        return response, code

    response, code = checker.check_method_request()
    if code != OK:
        return response, code

    match checker.methodRequest.method:
        case "online_score":
            response, code = checker.check_online_scoring()
            if code != OK:
                return response, code
            s = OnlineScoreRequest(args=dict(checker.methodRequest.arguments))
            ctx["has"] = s.get_filled_fields()
            score = get_score(store=None, phone=s.phone, email=s.email, birthday=s.birthday, gender=s.gender,
                              first_name=s.first_name, last_name=s.last_name,
                              is_admin=check_auth(checker.methodRequest))
            return score, OK
        case "clients_interests":
            response, code = checker.check_clients_interests()
            if code != OK:
                return response, code
            client_ids = checker.methodRequest.arguments.get("client_ids")
            ctx["nclients"] = len(client_ids)
            return get_interests(store=None, cid=client_ids), OK


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_post(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode('utf-8'))
        return


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", action="store", type=int, default=8080)
    parser.add_argument("-l", "--log", action="store", default=None)
    args = parser.parse_args()
    logging.basicConfig(filename=args.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", args.port), MainHTTPHandler)
    logging.info("Starting server at %s" % args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
