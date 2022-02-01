import argparse
import os
import json
import yaml
import shutil
import requests
import re
from logging import getLogger, config
from ansible.cli.galaxy import GalaxyCLI
from ansible.cli.galaxy import validate_collection_path, find_existing_collections
from ansible.galaxy.collection.concrete_artifact_manager import (
    ConcreteArtifactsManager,
)
from ansible.module_utils._text import to_text, to_bytes
from ansible.galaxy.collection import _resolve_depenency_map
from ansible import context

logger = getLogger(__name__)
with open('log_config.json', 'r') as f:
    log_conf = json.load(f)
config.dictConfig(log_conf)


class CollectionDependencyAnalyzer:
    def __init__(self, requirements_file, tmp_dir, policy):
        logger.info("init CollectionDependencyAnalyzer")
        self.requirements_file = GalaxyCLI._resolve_path(requirements_file)
        self.policy = GalaxyCLI._resolve_path(policy)
        if tmp_dir != "" and tmp_dir is not None:
            self.tmp_dir = GalaxyCLI._resolve_path(tmp_dir)
        else:
            tmp = os.path.join(os.getcwd(), "tmp")
            if not os.path.exists(tmp):
                logger.info("creating tmp dir...")
                os.mkdir(tmp)
            self.tmp_dir = tmp
        
        concrete_artifact_manager = ConcreteArtifactsManager(os.getcwd(), validate_certs=False)
        self.camanager = concrete_artifact_manager
        galaxy_args = ['ansible-galaxy', 'collection', 'install', '-r', self.requirements_file,
                   '-p', self.tmp_dir]
        self.gcli = GalaxyCLI(args=galaxy_args)
        # self.gcli.run()

    def install_collection(self):
        logger.info("install collection")
        # galaxy_args = ['ansible-galaxy', 'collection', 'install', '-r', self.requirements_file,
        #            '-p', self.tmp_dir]
        # ToDo:check if empty dir
        dir = os.listdir(self.tmp_dir)
        if len(dir) != 0:
            msg = "clean up tmp dir because tmp dir is not empty: {}".format(self.tmp_dir)
            logger.info(msg)
            shutil.rmtree(self.tmp_dir)
            os.mkdir(self.tmp_dir)
        # install
        self.gcli.run()
        # GalaxyCLI(args=galaxy_args).run()

    def analyze_installed_collection(self):
        analyzed_collections = []
        # get installed collections
        collections = self.list_installed_collection()
        # get download info from dependency map
        depmap_data = self.get_data_from_depenency_map()
        for collection in collections:
            name = collection.name
            namespace = collection.namespace
            version = collection.ver
            local_path = to_text(collection.src)
            repository, dependencies = self.analyze_manifest_file(local_path)
            download_count, score, survey_count, deprecated = self.get_state_from_galaxy(namespace, name, version)
            dinfo = self.get_download_info(namespace, name, version, depmap_data)
            # Data to be used for verification
            cdata = {"name": name, 
            "namespace": namespace, 
            "collection_info":{
                "version": version, 
                "local_path": local_path,
                "repository": repository,
                "dependencies": dependencies,
                "sha256_hash": dinfo["sha256_hash"],
                "type": dinfo["type"],
                "src": dinfo["src"]
            },
            "state":{
                "download_count": download_count,
                "community_score": score,
                "community_survey_count": survey_count
            }
            }
            # check dependency
            validate_res = self.validate_collection(self.policy, cdata)
            cdata["valid"] = validate_res
            analyzed_collections.append(cdata)
        return analyzed_collections
    
    def validate_collection(self, policy, collection):
        valid = False
        with open(policy) as f:
            rules = yaml.load(f)
        msg = 'policy: {}'.format(rules)
        logger.debug(msg)
        # check allow condition
        for rule in rules["allow_condition"]:
            dc = False
            cs = False
            csc = False
            if "download_count" in rule:
                if type(collection["state"]["download_count"]) is int:
                    if  collection["state"]["download_count"] >= rule["download_count"]:
                        dc = True
            else:
                dc = True
            if "community_score" in rule:
                if type(collection["state"]["community_score"]) is float:
                    if  collection["state"]["community_score"] >= rule["community_score"]:
                        cs = True  
            else:
                cs = True
            if "community_survey_count" in rule:
                if type(collection["state"]["community_survey_count"]) is int:
                    if  collection["state"]["community_survey_count"] >= rule["community_survey_count"]:
                        csc = True  
            else:
                csc = True
            if dc and cs and csc:
                valid = True
        # check whitelist
        if not valid:
            logger.debug("whitelist check...")
            for rule in rules["allow_list"]:
                name_match = False
                ns_match = False
                if "name" in rule:
                    name_match = self.MatchPattern(rule["name"], collection["name"])
                else:
                    name_match = True
                if "namespace" in rule:
                    ns_match = self.MatchPattern(rule["namespace"], collection["namespace"])
                else:
                    ns_match = True
                if name_match and ns_match:
                    valid = True
        return valid

    def MatchPattern(self, pattern, value): 
        pattern = pattern.replace(' ', '')
        if pattern == "":
            return True
        elif pattern == "*":
            return True
        elif "*" in pattern:
            m = re.match(pattern, value)
            return m
        elif pattern == value:
            return True
        # elif  "," in pattern:
        #     patterns = pattern.split(",")
        #     return MatchWithPatternArray(value, patterns)
        else:
            return False
        

    def list_installed_collection(self):
        collections = []
        logger.info("list installed collection")
        collection_path = os.path.join(self.tmp_dir, 'ansible_collections')
        # list all collections
        collection_path = validate_collection_path(collection_path)
        if os.path.isdir(collection_path):
            collections = list(find_existing_collections(
                collection_path, self.camanager,
            ))
            logger.debug(collections)
        return collections

    def get_data_from_depenency_map(self):
        collection_urls = []
        requirements = self.gcli._require_one_of_collections_requirements(
            "", self.requirements_file,
            artifacts_manager=self.camanager,
        )['collections']
        dep_map = _resolve_depenency_map(set(requirements),
            galaxy_apis=self.gcli.api_servers,
            preferred_candidates=None,
            concrete_artifacts_manager=self.camanager,
            no_deps=context.CLIARGS['no_deps'],
            allow_pre_release=context.CLIARGS['allow_pre_release'],
            upgrade=False)
        msg = 'resolve_depenency_map: {}'.format(dep_map)
        logger.debug(msg)
        for _, concrete_coll_pin in dep_map.copy().items():
            msg = '{} : type:{}'.format(to_text(concrete_coll_pin), concrete_coll_pin.type)
            logger.debug(msg)
            if concrete_coll_pin.is_file:
                ccp = {"name":to_text(concrete_coll_pin), "src": concrete_coll_pin.src, "ver": concrete_coll_pin.ver, "type":concrete_coll_pin.type , "sha256_hash": ""}
            elif concrete_coll_pin.type == "galaxy":
                url, sha256_hash, _ = self.camanager._galaxy_collection_cache[concrete_coll_pin]
                ccp = {"name":to_text(concrete_coll_pin), "src": url, "ver": concrete_coll_pin.ver, "type":concrete_coll_pin.type ,"sha256_hash": sha256_hash}
            logger.debug(ccp)
            collection_urls.append(ccp)
        return collection_urls

    def get_download_info(self, namespace, name, version, download_info):
        di_key = '{}.{}:{}'.format(namespace,name,version)
        dinfo = [di for di in download_info if di['name'] == di_key]
        dinfo = dinfo[0]
        return dinfo

    def analyze_manifest_file(self, local_path):
        repository = ""
        dependencies = ""
        manifest_path = os.path.join(local_path, 'MANIFEST.json')
        if os.path.exists(manifest_path):
            with open(manifest_path) as f:
                info = json.load(f)
                repository = info["collection_info"]["repository"]
                dependencies = info["collection_info"]["dependencies"]
        return repository, dependencies
    
    def get_galaxy_collections(self,name):
        # add info "repository", "download "
        if name != "":
            api_url = "https://galaxy.ansible.com/api/internal/ui/search/?keywords=KEYWORDS&order_by=-relevance&type=collection"
            api_url = api_url.replace("KEYWORDS", name)
            msg = 'api url: {}'.format(api_url)
            logger.debug(msg)
        else:
            api_url = 'https://galaxy.ansible.com/api/internal/ui/search/?type=collection' 
        response = requests.get(api_url)
        galaxy_collections = response.json()
        # print(json.dumps(galaxy_collections, indent=2))
        # gi = GalaxyInstance('https://galaxy.ansible.com')
        # libs = gi.libraries.get_libraries()
        # for collection in self.collections:
        #     # api_url = "https://usegalaxy.org/api/histories?order=name"
        #     response = requests.get(api_url)
        #     print(response.json())
        return galaxy_collections["collection"]["results"]

    def get_state_from_galaxy(self, namespace, name, version):
        download_count = ""
        community_score = ""
        community_survey_count = ""
        deprecated = False
        galaxy_collections = self.get_galaxy_collections(name)
        for gc in galaxy_collections:
            if namespace == gc["namespace"]["name"] and name == gc["name"]:
                if gc["latest_version"]["version"] != version:
                    msg = 'version is not matched: installed version {}, latest version {}'.format(version, gc["latest_version"]["version"] )
                    logger.warning(msg)
                    return download_count, community_score, community_survey_count, deprecated
                msg = 'matched collection: {}:{}:{}'.format(gc["namespace"]["name"] , gc["name"], gc["latest_version"]["version"])
                logger.debug(msg)
                download_count = gc["download_count"]
                community_score = gc["community_score"]
                community_survey_count = gc["community_survey_count"]
                deprecated = gc["deprecated"]
                msg = 'matched collection info: download_count:{}, community_score:{}, community_survey_count:{}'.format(download_count, community_score, community_survey_count)
                logger.debug(msg)
                return download_count, community_score, community_survey_count, deprecated
        return download_count, community_score, community_survey_count, deprecated

    def make_final_dicision(self, collections):
        valid_dependencies = True
        invalids = []
        for collection in collections:
            if not collection["valid"]:
                valid_dependencies = False
                invalids.append('{}:{}'.format(collection["namespace"], collection["name"]))
        if valid_dependencies:
            final_msg = "All dependent collections are valid!"
        else:
            final_msg = "Contains invalid collections: {}".format(",".join(invalids)) 
        return valid_dependencies, final_msg

def main():
    parser = argparse.ArgumentParser(
        prog='analyzer.py',
        description='Ansible Collection Analyzer',
        epilog='end',
        add_help=True,
    )
    parser.add_argument('-r', '--requirements_file', help='requirements file')
    parser.add_argument('-d', '--download_path', help='tmp dir to download the collections to.')
    parser.add_argument('-o', '--output_file', help='file to export result.')
    parser.add_argument('-p', '--policy', help='allow policy.')
    
    args = parser.parse_args()
    requirements_file = args.requirements_file
    output_file = args.output_file
    tmp_dir = args.download_path
    policy = args.policy
    cda = CollectionDependencyAnalyzer(requirements_file, tmp_dir, policy)
    cda.install_collection()
    clist = cda.analyze_installed_collection()
    final_dicision, msg = cda.make_final_dicision(clist)
    res = {"collections": clist, "roles": []}
    with open(output_file, 'w') as f:
        json.dump(res, f, ensure_ascii=False, indent=4)
    print("dependency check: ", final_dicision)
    print(msg)
    return final_dicision, msg

if __name__ == '__main__':
    main()