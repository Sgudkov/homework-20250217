import random


class ScoreResponseStruct:
    def __init__(self, score: float):
        self.score = score


class InterestResponseStruct(object):
    def __init__(self, cid: list, interest: list):
        self.resp = {}
        for i in cid:
            self.resp[i] = random.sample(interest, len(cid))


def get_score(phone, email, birthday=None, gender=None, first_name=None, last_name=None, store=None, is_admin=bool):
    score = 0
    if phone:
        score += 1.5
    if email:
        score += 1.5
    if birthday and gender:
        score += 1.5
    if first_name and last_name:
        score += 0.5
    score = 42 if is_admin else score
    return ScoreResponseStruct(score).__dict__


def get_interests(store, cid):
    interests = ["cars", "pets", "travel", "hi-tech", "sport", "music", "books", "tv", "cinema", "geek", "otus"]
    return InterestResponseStruct(cid, interests).resp
