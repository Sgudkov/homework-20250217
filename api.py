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
    nullable: bool = False


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
            if not value is None:
                fields.append(key)
        return fields[:]


class ClientsInterestsRequest(RequestFieldsParser, object):

    def __init__(self, args):
        self.client_ids = ClientIDsField(required=True)
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

    def __init__(self, args):
        self.account = CharField(required=False, nullable=True)
        self.login = CharField(required=True, nullable=True)
        self.token = CharField(required=True, nullable=True)
        self.arguments = ArgumentsField(required=True, nullable=True)
        self.method = CharField(required=True, nullable=False)
        super().__init__(args=args)
        v = 1

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


class RequestChecker(object):

    def __init__(self):
        self.request = None

    def check_empty_request(self):
        if self.request is None:
            return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

    def check_bad_auth(self):
        if check_auth(self.request.get("body")):
            return ERRORS.get(FORBIDDEN), FORBIDDEN

    def check_invalid_method_request(self):
        if not self.request.get("method") in ["online_score", "clients_interests"]:
            return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

    def check_invalid_score_request(self):
        request = self.request
        fields_dc: OnlineScoreRequest = request.get("arguments")
        if fields_dc is None or bool(fields_dc) is False:
            return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

        fields = OnlineScoreRequest(request.get("arguments"))

        if not (fields.phone and fields.email) or not (fields.first_name and fields.last_name) or not (
                fields.gender and fields.birthday):
            return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

        if len(fields.phone) != 11 or fields.phone[0] != 7:
            return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', fields.email):
            return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

        format = "%d-%m-%Y"
        try:
            date_validate = bool(datetime.datetime.strptime(fields.birthday, format))
        except ValueError:
            date_validate = True

        if date_validate:
            return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

    def check_ok_score_request(self):
        pass

    def check_ok_score_admin_request(self):
        pass

    def check_invalid_interests_request(self):
        pass

    def check_ok_interests_request(self):
        pass


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode('utf-8')).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode('utf-8')).hexdigest()
    return digest == request.token


def check_method_fields(request):
    match request.get("method"):
        case "online_score":
            fields_dc: OnlineScoreRequest = request.get("arguments")
            if fields_dc is None or bool(fields_dc) is False:
                return True

            fields = OnlineScoreRequest(dict(request.get("arguments")))

            if isinstance(fields.phone, PhoneField) and isinstance(fields.email, EmailField):
                return True
            elif isinstance(fields.first_name, CharField) and isinstance(fields.last_name, CharField):
                return True
            elif isinstance(fields.gender, GenderField) and isinstance(fields.birthday, BirthDayField):
                return True

            if (len(str(fields.phone)) != 11 or int(str(fields.phone)[0]) != 7) and fields.phone is not None:
                return True

            if not fields.email is None and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
                                                         fields.email):
                return True

            if fields.birthday is None: return False

            format = "%d.%m.%Y"

            try:
                date_valid = bool(datetime.datetime.strptime(fields.birthday, format))
            except ValueError:
                date_invalid = False

            if not date_valid:
                return True

        case "clients_interests":
            pass


def check_request(request):
    if request is None:
        return True

    if request.get("method") in ["online_score", "clients_interests"]:
        return check_method_fields(request)
    else:
        return True


def method_handler(request, ctx, store):
    try:
        r = MethodRequest(args=dict(request.get("body")))
        if not check_auth(r):
            response = ERRORS.get(FORBIDDEN)
            code = FORBIDDEN
            return response, code
    except Exception as e:
        return ERRORS.get(FORBIDDEN), FORBIDDEN

    if check_request(request.get("body")):
        return ERRORS.get(INVALID_REQUEST), INVALID_REQUEST

    match r.method:
        case "online_score":
            s = OnlineScoreRequest(dict(r.arguments))
            ctx["has"] = s.get_filled_fields()
            score = get_score(store=None, phone=s.phone, email=s.email, birthday=s.birthday, gender=s.gender,
                              first_name=s.first_name, last_name=s.last_name, is_admin=check_auth(r))
            return score, OK
        case "clients_interests":
            return get_interests(r.arguments), OK


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
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
