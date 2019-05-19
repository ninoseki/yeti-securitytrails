from datetime import datetime
import json
import logging
from dateutil.parser import parse
import requests

from core.analytics import OneShotAnalytics
from core.config.config import yeti_config
from core.observables import Hostname, Ip, Email, Text

logger = logging.getLogger("Yeti-ST")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler("/var/log/yeti/st.log")
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
fh.setFormatter(formatter)
logger.addHandler(fh)

SOURCE = "SecurityTrails"


def convert_to_datetime(time):
    if time is None or time == 0:
        return None

    if isinstance(time, (str, unicode)):
        return parse(time)

    time = int(time) / 1000
    return datetime.fromtimestamp(time)


def whois_links(observable, data):
    links = set()
    created_date = data.get("createdDate")
    expires_date = data.get("expiresDate")

    first_seen = convert_to_datetime(created_date)
    last_seen = convert_to_datetime(expires_date)

    registrar_name = data.get("registrarName")
    if registrar_name is not None:
        node = Text.get_or_create(value=registrar_name)
        try:
            links.update(observable.link_to(
                node, "Registrar name", SOURCE, first_seen, last_seen))
        except Exception as e:
            logger.error(e.message)

    contacts = data.get("contact", [])
    for contact in contacts:
        email = contact.get("email")
        if email is not None:
            node = Email.get_or_create(value=email)
            try:
                links.update(observable.link_to(
                    node, "Contact email", SOURCE), first_seen, last_seen)
            except Exception as e:
                logger.error(e.message)

    name_servers = data.get("nameServers", [])
    name_servers = name_servers if name_servers is not None else []
    for name_server in name_servers:
        node = Hostname.get_or_create(value=name_server)
        try:
            links.update(observable.link_to(
                node, "Name server", SOURCE), first_seen, last_seen)
        except Exception as e:
            logger.error(e.message)

    return list(links)


def history_links(observable, data):
    links = set()
    data_type = data.get("type", "").encode("utf-8")

    table = {
        "a/ipv4": {"key": "ip", "class": Ip, "label": "A record"},
        "mx": {"key": "host", "class": Hostname, "label": "MX record"},
        "ns": {"key": "nameserver", "class": Hostname, "label": "NS record"},
        "soa": {"key": "email", "class": Hostname, "label": "SOA record"}
    }

    item = table.get(data_type, {})
    key = item.get("key")
    klass = item.get("class")
    label = item.get("label")

    records = data.get("records", [])
    for record in records:
        first_seen = convert_to_datetime(record.get("first_seen"))
        last_seen = convert_to_datetime(record.get("last_seen"))
        values = record.get("values", [])
        values = values if isinstance(values, list) else [values]
        for value in values:
            v = value.get(key)
            try:
                node = klass.get_or_create(value=v)
                links.update(
                    observable.link_to(node, label, SOURCE, first_seen, last_seen))
            except Exception as e:
                logger.error(e.message)

    return list(links)


def current_dns_links(observable, data):
    links = set()

    table = {
        "a": {"key": "ip", "class": Ip, "label": "A record"},
        "mx": {"key": "host", "class": Hostname, "label": "MX record"},
        "ns": {"key": "nameserver", "class": Hostname, "label": "NS record"},
        "soa": {"key": "email", "class": Hostname, "label": "SOA record"}
    }

    current_dns = data.get("current_dns", {})

    for data_type in table:
        item = table.get(data_type, {})
        key = item.get("key")
        klass = item.get("class")
        label = item.get("label")

        record = current_dns.get(data_type, {})

        first_seen = convert_to_datetime(record.get("first_seen"))
        values = record.get("values", [])
        values = values if isinstance(values, list) else [values]
        for value in values:
            v = value.get(key)
            try:
                node = klass.get_or_create(value=v)
                links.update(
                    observable.link_to(node, label, SOURCE, first_seen))
            except Exception as e:
                logger.error(e.message)

    return list(links)


class SecurityTrailsApi(object):
    settings = {
        "securitytrails_api_key": {
            "name": "SecurityTrails API Key",
            "description": "API Key provided by SecurityTrails."
        }
    }

    BASE_URL = "https://api.securitytrails.com/v1"

    @staticmethod
    def get(uri, settings, params={}):
        url = "{}{}".format(SecurityTrailsApi.BASE_URL, uri)
        api_key = settings["securitytrails_api_key"]

        session = requests.session()
        session.headers.update(
            {"APIKEY": api_key, "Content-Type": "application/json"})
        res = session.get(url, params=params, proxies=yeti_config.proxy)
        try:
            res.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error(e)
            return {}

        return res.json()

    @staticmethod
    def post(uri, settings, params={}):
        url = "{}{}".format(SecurityTrailsApi.BASE_URL, uri)
        api_key = settings["securitytrails_api_key"]

        session = requests.session()
        session.headers.update(
            {"APIKEY": api_key, "Content-Type": "application/json"})
        res = session.post(url, json.dumps(params), proxies=yeti_config.proxy)
        try:
            res.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error(e)
            return {}

        return res.json()


class SecurityTrailsSubdomains(OneShotAnalytics, SecurityTrailsApi):
    default_values = {
        "group": "SecurityTrails",
        "name": "ST subdomains",
        "description": "Find all known subdomains."
    }

    ACTS_ON = ["Hostname"]

    @staticmethod
    def analyze(observable, results):
        links = set()

        domain = observable.value
        data = SecurityTrailsApi.get(
            "/domain/{}/subdomains".format(domain), results.settings)
        results.update(raw=json.dumps(data, indent=2))

        records = data.get("subdomains", [])
        for record in records:
            value = "{}.{}".format(record, domain)
            try:
                subdomain = Hostname.get_or_create(value=value)
                links.update(
                    observable.link_to(subdomain, "Subdomain", SOURCE))
            except Exception as e:
                logger.error(e.message)

        return list(links)


class SecurityTrailsAssociatedDomains(OneShotAnalytics, SecurityTrailsApi):
    default_values = {
        "group": "SecurityTrails",
        "name": "ST associated domains",
        "description": "Find all associated domains."
    }

    ACTS_ON = ["Hostname"]

    @staticmethod
    def analyze(observable, results):
        links = set()

        domain = observable.value
        data = SecurityTrailsApi.get(
            "/domain/{}/associated".format(domain), results.settings)
        results.update(raw=json.dumps(data, indent=2))

        records = data.get("subdomains", [])
        for record in records:
            hostname = record.get("hostname")
            if hostname == domain:
                continue

            try:
                associated_domain = Hostname.get_or_create(value=hostname)
                links.update(
                    observable.link_to(associated_domain, "Associated domain", SOURCE))
            except Exception as e:
                logger.error(e.message)

        return list(links)


class SecurityTrailsReverseIP(OneShotAnalytics, SecurityTrailsApi):

    default_values = {
        "group": "SecurityTrails",
        "name": "ST reverse IP",
        "description": "Reverse IP lookup."
    }

    ACTS_ON = ["Ip"]

    @staticmethod
    def analyze(observable, results):
        links = set()

        ipv4 = observable.value
        params = {"filter": {"ipv4": ipv4}}

        data = SecurityTrailsApi.post(
            "/domains/list", results.settings, params)
        results.update(raw=json.dumps(data, indent=2))

        records = data.get("records", [])
        for record in records:
            hostname = record.get("hostname")
            try:
                node = Hostname.get_or_create(value=hostname)
                links.update(
                    node.link_to(observable, "A record", SOURCE))
            except Exception as e:
                logger.error(e.message)

        return list(links)


class SecurityTrailsDomainLookup(OneShotAnalytics, SecurityTrailsApi):

    default_values = {
        "group": "SecurityTrails",
        "name": "ST domain",
        "description": "Domain lookup."
    }

    ACTS_ON = ["Hostname"]

    @staticmethod
    def analyze(observable, results):
        links = set()

        domain = observable.value
        data = SecurityTrailsApi.get(
            "/domain/{}".format(domain), results.settings)
        results.update(raw=json.dumps(data, indent=2))

        return current_dns_links(observable, data)


class SecurityTrailsARecordHistory(OneShotAnalytics, SecurityTrailsApi):

    default_values = {
        "group": "SecurityTrails",
        "name": "ST A record history",
        "description": "A record history lookup."
    }

    ACTS_ON = ["Hostname"]

    @staticmethod
    def analyze(observable, results):
        domain = observable.value
        data = SecurityTrailsApi.get(
            "/history/{}/dns/a".format(domain), results.settings)
        results.update(raw=json.dumps(data, indent=2))

        return history_links(observable, data)


class SecurityTrailsMXRecordHistory(OneShotAnalytics, SecurityTrailsApi):

    default_values = {
        "group": "SecurityTrails",
        "name": "ST MX record history",
        "description": "MX record history lookup."
    }

    ACTS_ON = ["Hostname"]

    @staticmethod
    def analyze(observable, results):
        domain = observable.value
        data = SecurityTrailsApi.get(
            "/history/{}/dns/mx".format(domain), results.settings)
        results.update(raw=json.dumps(data, indent=2))

        return history_links(observable, data)


class SecurityTrailsNSRecordHistory(OneShotAnalytics, SecurityTrailsApi):

    default_values = {
        "group": "SecurityTrails",
        "name": "ST NS record history",
        "description": "NS record history lookup."
    }

    ACTS_ON = ["Hostname"]

    @staticmethod
    def analyze(observable, results):
        domain = observable.value
        data = SecurityTrailsApi.get(
            "/history/{}/dns/ns".format(domain), results.settings)
        results.update(raw=json.dumps(data, indent=2))

        return history_links(observable, data)


class SecurityTrailsSOARecordHistory(OneShotAnalytics, SecurityTrailsApi):

    default_values = {
        "group": "SecurityTrails",
        "name": "ST SOA record history",
        "description": "SOA record history lookup."
    }

    ACTS_ON = ["Hostname"]

    @staticmethod
    def analyze(observable, results):
        domain = observable.value
        data = SecurityTrailsApi.get(
            "/history/{}/dns/soa".format(domain), results.settings)
        results.update(raw=json.dumps(data, indent=2))

        return history_links(observable, data)


class SecurityTrailsWhois(OneShotAnalytics, SecurityTrailsApi):

    default_values = {
        "group": "SecurityTrails",
        "name": "ST Whois",
        "description": "Whois lookup."
    }

    ACTS_ON = ["Hostname"]

    @staticmethod
    def analyze(observable, results):
        domain = observable.value

        data = SecurityTrailsApi.get(
            "/domain/{}/whois".format(domain), results.settings)
        results.update(raw=json.dumps(data, indent=2))

        return whois_links(observable, data)


class SecurityTrailsWhoisHistory(OneShotAnalytics, SecurityTrailsApi):

    default_values = {
        "group": "SecurityTrails",
        "name": "ST Whois history",
        "description": "Whois history lookup."
    }

    ACTS_ON = ["Hostname"]

    @staticmethod
    def analyze(observable, results):
        links = set()
        domain = observable.value

        data = SecurityTrailsApi.get(
            "/history/{}/whois".format(domain), results.settings)
        results.update(raw=json.dumps(data, indent=2))

        items = data.get("result", {}).get("items", [])
        for item in items:
            links.update(whois_links(observable, item))

        return list(links)


class SecurityTrailsReverseWhois(OneShotAnalytics, SecurityTrailsApi):

    default_values = {
        "group": "SecurityTrails",
        "name": "ST reverse Whois",
        "description": "Reverse Whois lookup."
    }

    ACTS_ON = ["Email"]

    @staticmethod
    def analyze(observable, results):
        links = set()

        email = observable.value
        params = {"filter": {"whois_email": email}}

        data = SecurityTrailsApi.post(
            "/domains/list", results.settings, params)
        results.update(raw=json.dumps(data, indent=2))

        records = data.get("records", [])

        for record in records:
            hostname = record.get("hostname")
            try:
                node = Hostname.get_or_create(value=hostname)
                links.update(node.link_to(
                    observable, "Contact email", SOURCE))
            except Exception as e:
                logger.error(e.message)

        return list(links)
