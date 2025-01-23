"""
    Bloodhound importer in python.
    Queries are borrowed from the BloodhoundAD project.
"""

from dataclasses import dataclass
from tempfile import NamedTemporaryFile
from zipfile import ZipFile
from os.path import basename
import codecs
import ijson
import logging
import neo4j


@dataclass
class Query:
    query: str
    properties: dict


SYNC_COUNT = 100
OBJECT_DCSYNC = dict()
OBJECT_GET_CHANGE = list()
OBJECT_GET_CHANGE_ALL = list()
GROUP_MAPPING = dict()


def build_add_edge_query(source_label: str, target_label: str, edge_type: str, edge_props: str) -> str:
    """Build a standard edge insert query based on the given params"""
    insert_query = 'UNWIND $props AS prop MERGE (n:Base {{objectid: prop.source}}) SET n:{0} MERGE (m:Base {{objectid: prop.target}}) SET m:{1} MERGE (n)-[r:{2} {3}]->(m)'
    return insert_query.format(source_label, target_label, edge_type, edge_props)


async def process_ace_list(ace_list: list, objectid: str, objecttype: str, tx: neo4j.Transaction) -> None:
    dcsync = list()
    for entry in ace_list:
        principal = entry['PrincipalSID']
        principaltype = entry['PrincipalType']
        right = entry['RightName']
        if objectid == principal:
            continue
        query = build_add_edge_query(
            principaltype, objecttype, right, '{isacl: true, isinherited: prop.isinherited}')
        props = dict(
            source=principal,
            target=objectid,
            isinherited=entry['IsInherited'],
        )
        await tx.run(query, props=props)
        # domain dcsync
        if objectid == objectid[:41] and objectid[:8] == 'S-1-5-21':
            if right == 'GetChangesAll':
                OBJECT_GET_CHANGE_ALL.append(principal)
            if right == 'GetChanges':
                OBJECT_GET_CHANGE.append(principal)
            if (principal in OBJECT_GET_CHANGE) and (principal in OBJECT_GET_CHANGE_ALL):
                if principal not in dcsync:
                    query = build_add_edge_query(
                        principaltype, objecttype, 'DCSync', '{isacl: true, isinherited: prop.isinherited}')
                    await tx.run(query, props=props)
                    dcsync.append(principal)
            


async def process_spntarget_list(spntarget_list: list, objectid: str, tx: neo4j.Transaction) -> None:
    for entry in spntarget_list:
        query = build_add_edge_query(
            'User', 'Computer', 'WriteSPN', '{isacl: false, port: prop.port}')
        props = dict(
            source=objectid,
            target=entry['ComputerSID'],
            port=entry['Port'],
        )
        await tx.run(query, props=props)


async def add_constraints(tx: neo4j.Transaction):
    """Adds bloodhound contraints to neo4j

    Arguments:
        tx {neo4j.Transaction} -- Neo4j transaction.
    """
    await tx.run('CREATE CONSTRAINT base_objectid_unique ON (b:Base) ASSERT b.objectid IS UNIQUE')
    await tx.run('CREATE CONSTRAINT computer_objectid_unique ON (c:Computer) ASSERT c.objectid IS UNIQUE')
    await tx.run('CREATE CONSTRAINT domain_objectid_unique ON (d:Domain) ASSERT d.objectid IS UNIQUE')
    await tx.run('CREATE CONSTRAINT group_objectid_unique ON (g:Group) ASSERT g.objectid IS UNIQUE')
    await tx.run('CREATE CONSTRAINT user_objectid_unique ON (u:User) ASSERT u.objectid IS UNIQUE')
    await tx.run("CREATE CONSTRAINT ON (c:User) ASSERT c.name IS UNIQUE")
    await tx.run("CREATE CONSTRAINT ON (c:Computer) ASSERT c.name IS UNIQUE")
    await tx.run("CREATE CONSTRAINT ON (c:Group) ASSERT c.name IS UNIQUE")
    await tx.run("CREATE CONSTRAINT ON (c:Domain) ASSERT c.name IS UNIQUE")
    await tx.run("CREATE CONSTRAINT ON (c:OU) ASSERT c.guid IS UNIQUE")
    await tx.run("CREATE CONSTRAINT ON (c:GPO) ASSERT c.name IS UNIQUE")


async def parse_ou(tx: neo4j.Transaction, ou: dict):
    """Parses a single ou.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j session
        ou {dict} -- Single ou object.
    """
    identifier = ou['ObjectIdentifier'].upper()
    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:OU SET n += prop.map'
    props = {'map': ou['Properties'], 'source': identifier}
    await tx.run(property_query, props=props)

    if 'Aces' in ou and ou['Aces'] is not None:
        await process_ace_list(ou['Aces'], identifier, "OU", tx)

    if 'ChildObjects' in ou and ou['ChildObjects']:
        targets = ou['ChildObjects']
        for target in targets:
            query = build_add_edge_query(
                'OU', target['ObjectType'], 'Contains', '{isacl: false}')
            await tx.run(query, props=dict(source=identifier, target=target['ObjectIdentifier']))

    if 'Links' in ou and ou['Links']:
        query = build_add_edge_query(
            'GPO', 'OU', 'GPLink', '{isacl: false, enforced: prop.enforced}')
        for gpo in ou['Links']:
            await tx.run(query, props=dict(source=gpo['GUID'].upper(), target=identifier, enforced=gpo['IsEnforced']))

    options = [
        ('LocalAdmins', 'AdminTo'),
        ('PSRemoteUsers', 'CanPSRemote'),
        ('DcomUsers', 'ExecuteDCOM'),
        ('RemoteDesktopUsers', 'CanRDP'),
    ]

    if 'GPOChanges' in ou and ou['GPOChanges']:
        gpo_changes = ou['GPOChanges']
        affected_computers = gpo_changes['AffectedComputers']
        for option, edge_name in options:
            if option in gpo_changes and gpo_changes[option]:
                targets = gpo_changes[option]
                for target in targets:
                    query = build_add_edge_query(
                        target['ObjectType'], 'Computer', edge_name, '{isacl: false, fromgpo: true}')
                    for computer in affected_computers:
                        await tx.run(query, props=dict(source=computer['ObjectIdentifier'], target=target['ObjectIdentifier']))


async def parse_gpo(tx: neo4j.Transaction, gpo: dict):
    """Parses a single GPO.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j transaction
        gpo {dict} -- Single gpo object.
    """
    identifier = gpo['ObjectIdentifier']

    query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:GPO SET n += prop.map'
    props = {'map': gpo['Properties'], 'source': identifier}
    await tx.run(query, props=props)

    if "Aces" in gpo and gpo["Aces"] is not None:
        await process_ace_list(gpo['Aces'], identifier, "GPO", tx)


async def parse_computer(tx: neo4j.Transaction, computer: dict):
    """Parse a computer object.

    Arguments:
        session {neo4j.Transaction} -- Neo4j transaction
        computer {dict} -- Single computer object.
    """
    identifier = computer['ObjectIdentifier']

    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:Computer SET n += prop.map'
    props = {'map': computer['Properties'], 'source': identifier}

    await tx.run(property_query, props=props)

    if 'PrimaryGroupSID' in computer and computer['PrimaryGroupSID']:
        query = build_add_edge_query(
            'Computer', 'Group', 'MemberOf', '{isacl:false}')
        await tx.run(query, props=dict(source=identifier, target=computer['PrimaryGroupSID']))
        primary_sid = computer['PrimaryGroupSID']
        is_change = (primary_sid in OBJECT_GET_CHANGE)
        if is_change:
            if identifier not in OBJECT_DCSYNC:
                OBJECT_DCSYNC[identifier] = {}
            OBJECT_DCSYNC[identifier]['change'] = True
        is_change_all = (primary_sid in OBJECT_GET_CHANGE_ALL)
        if is_change_all:
            if identifier not in OBJECT_DCSYNC:
                OBJECT_DCSYNC[identifier] = {}
            OBJECT_DCSYNC[identifier]['change_all'] = True
        if (is_change and is_change_all):
            props = dict(
                source=identifier,
                target=identifier[:41],
            )
            query = build_add_edge_query(
                'Computer', 'Domain', 'DCSync', '{isacl: true, isinherited: false}')
            await tx.run(query, props=props)
        elif OBJECT_DCSYNC.get(identifier):
            if (OBJECT_DCSYNC[identifier].get('change') and OBJECT_DCSYNC[identifier].get('change_all')):
                props = dict(
                    source=identifier,
                    target=identifier[:41],
                )
                query = build_add_edge_query(
                    'Computer', 'Domain', 'DCSync', '{isacl: true, isinherited: false}')
                await tx.run(query, props=props)

    if 'AllowedToDelegate' in computer and computer['AllowedToDelegate']:
        query = build_add_edge_query(
            'Computer', 'Group', 'MemberOf', '{isacl:false}')
        for entry in computer['AllowedToDelegate']:
            await tx.run(query, props=dict(source=identifier, target=entry['ObjectIdentifier']))

    # (Property name, Edge name, Use "Results" format)
    options = [
        ('LocalAdmins', 'AdminTo', True),
        ('RemoteDesktopUsers', 'CanRDP', True),
        ('DcomUsers', 'ExecuteDCOM', True),
        ('PSRemoteUsers', 'CanPSRemote', True),
        ('AllowedToAct', 'AllowedToAct', False),
        ('AllowedToDelegate', 'AllowedToDelegate', False),
    ]

    for option, edge_name, use_results in options:
        if option in computer:
            targets = computer[option]['Results'] if use_results else computer[option]
            for target in targets:
                query = build_add_edge_query(
                    target['ObjectType'], 'Computer', edge_name, '{isacl:false, fromgpo: false}')
                await tx.run(query, props=dict(source=target['ObjectIdentifier'], target=identifier))

    # (Session type, source)
    session_types = [
        ('Sessions', 'netsessionenum'),
        ('PrivilegedSessions', 'netwkstauserenum'),
        ('RegistrySessions', 'registry'),
    ]

    for session_type, source in session_types:
        if session_type in computer and computer[session_type]['Results']:
            query = build_add_edge_query(
                'Computer', 'User', 'HasSession', '{isacl:false, source:"%s"}' % source)
            for entry in computer[session_type]['Results']:
                await tx.run(query, props=dict(target=entry['UserSID'], source=entry['ComputerSID']))

    if 'Aces' in computer and computer['Aces'] is not None:
        await process_ace_list(computer['Aces'], identifier, "Computer", tx)


async def parse_user(tx: neo4j.Transaction, user: dict):
    """Parse a user object.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j session
        user {dict} -- Single user object from the bloodhound json.
    """
    identifier = user['ObjectIdentifier']
    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:User SET n += prop.map'
    props = {'map': user['Properties'], 'source': identifier}
    await tx.run(property_query, props=props)

    if 'PrimaryGroupSID' in user and user['PrimaryGroupSID']:
        query = build_add_edge_query(
            'User', 'Group', 'MemberOf', '{isacl: false}')
        await tx.run(query, props=dict(source=identifier, target=user['PrimaryGroupSID']))
        primary_sid = user['PrimaryGroupSID']
        is_change = (primary_sid in OBJECT_GET_CHANGE)
        if is_change:
            if identifier not in OBJECT_DCSYNC:
                OBJECT_DCSYNC[identifier] = {}
            OBJECT_DCSYNC[identifier]['change'] = True
        is_change_all = (primary_sid in OBJECT_GET_CHANGE_ALL)
        if is_change_all:
            if identifier not in OBJECT_DCSYNC:
                OBJECT_DCSYNC[identifier] = {}
            OBJECT_DCSYNC[identifier]['change_all'] = True
        if (is_change and is_change_all):
            props = dict(
                source=identifier,
                target=identifier[:41],
            )
            query = build_add_edge_query(
                'User', 'Domain', 'DCSync', '{isacl: true, isinherited: false}')
            await tx.run(query, props=props)
        elif OBJECT_DCSYNC.get(identifier):
            if (OBJECT_DCSYNC[identifier].get('change') and OBJECT_DCSYNC[identifier].get('change_all')):
                props = dict(
                    source=identifier,
                    target=identifier[:41],
                )
                query = build_add_edge_query(
                    'User', 'Domain', 'DCSync', '{isacl: true, isinherited: false}')
                await tx.run(query, props=props)
    if 'AllowedToDelegate' in user and user['AllowedToDelegate']:
        query = build_add_edge_query(
            'User', 'Computer', 'AllowedToDelegate', '{isacl: false}')
        for entry in user['AllowedToDelegate']:
            await tx.run(query, props=dict(source=identifier, target=entry['ObjectIdentifier']))

    # TODO add HasSIDHistory objects

    if 'Aces' in user and user['Aces'] is not None:
        await process_ace_list(user['Aces'], identifier, "User", tx)

    if 'SPNTargets' in user and user['SPNTargets'] is not None:
        await process_spntarget_list(user['SPNTargets'], identifier, tx)


async def parse_group(tx: neo4j.Transaction, group: dict):
    """Parse a group object.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j Transaction
        group {dict} -- Single group object from the bloodhound json.
    """
    properties = group['Properties']
    domain = properties['domain']
    identifier = group['ObjectIdentifier']
    members = group['Members']
    if identifier not in GROUP_MAPPING:
        GROUP_MAPPING[identifier] = {}

    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:Group SET n += prop.map'
    props = {'map': properties, 'source': identifier}
    await tx.run(property_query, props=props)

    if 'Aces' in group and group['Aces'] is not None:
        await process_ace_list(group['Aces'], identifier, "Group", tx)

    for member in members:
        member_sid = member['ObjectIdentifier']
        member_type = member['ObjectType']
        if member_type == 'Group':
            GROUP_MAPPING[identifier][member_sid] = {}
        query = build_add_edge_query(
            member_type, 'Group', 'MemberOf', '{isacl: false}')
        await tx.run(query, props=dict(source=member_sid, target=identifier))
    # Domain users and Domain computers
    if identifier[-4:] == '-513' or identifier[-4:] == '-515':
        everyone = domain + '-S-1-1-0'
        authenticated = domain + '-S-1-5-11'
        query = build_add_edge_query(
            'Group', 'Group', 'MemberOf', '{isacl: false}')
        await tx.run(query, props=dict(source=identifier, target=everyone))
        query = build_add_edge_query(
            'Group', 'Group', 'MemberOf', '{isacl: false}')
        await tx.run(query, props=dict(source=identifier, target=authenticated))


def build_tree(root, data):
    tree = {}
    children = data.get(root, {})
    for child in children:
        tree[child] = build_tree(child, data)
    return tree


def flatten_tree_to_list(tree):
    keys = []
    for key, subtree in tree.items():
        keys.append(key)
        keys.extend(flatten_tree_to_list(subtree))
    return keys


async def parse_group2(tx: neo4j.Transaction, group: dict):
    identifier = group['ObjectIdentifier']
    members = group['Members']
    for member in members:
        member_sid = member['ObjectIdentifier']
        is_get_change_all = (identifier in OBJECT_GET_CHANGE_ALL)
        is_get_change = (identifier in OBJECT_GET_CHANGE)
        if is_get_change:
            if member_sid not in OBJECT_DCSYNC:
                OBJECT_DCSYNC[member_sid] = dict()
            OBJECT_DCSYNC[member_sid]['change'] = True
        if is_get_change_all:
            if member_sid not in OBJECT_DCSYNC:
                OBJECT_DCSYNC[member_sid] = dict()
            OBJECT_DCSYNC[member_sid]['change_all'] = True
        if OBJECT_DCSYNC.get(member_sid):
            if (((OBJECT_DCSYNC[member_sid].get('change')) and (OBJECT_DCSYNC[member_sid].get('change_all')))
                or
                    (is_get_change_all and is_get_change)):
                props = dict(
                    source=member_sid,
                    target=member_sid[:41],
                )
                query = build_add_edge_query(
                    member['ObjectType'], 'Domain', 'DCSync', '{isacl: true, isinherited: false}')
                await tx.run(query, props=props)


async def parse_domain(tx: neo4j.Transaction, domain: dict):
    """Parse a domain object.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j Transaction
        domain {dict} -- Single domain object from the bloodhound json.
    """
    identifier = domain['ObjectIdentifier']
    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:Domain SET n += prop.map'
    props = {'map': domain['Properties'], 'source': identifier}
    await tx.run(property_query, props=props)

    if 'Aces' in domain and domain['Aces'] is not None:
        await process_ace_list(domain['Aces'], identifier, 'Domain', tx)

    trust_map = {0: 'ParentChild', 1: 'CrossLink',
                 2: 'Forest', 3: 'External', 4: 'Unknown'}
    if 'Trusts' in domain and domain['Trusts'] is not None:
        query = build_add_edge_query('Domain', 'Domain', 'TrustedBy',
                                     '{sidfiltering: prop.sidfiltering, trusttype: prop.trusttype, transitive: prop.transitive, isacl: false}')
        for trust in domain['Trusts']:
            trust_type = trust['TrustType']
            direction = trust['TrustDirection']
            props = {}
            if direction in [1, 3]:
                props = dict(
                    source=identifier,
                    target=trust['TargetDomainSid'],
                    trusttype=trust_map[trust_type],
                    transitive=trust['IsTransitive'],
                    sidfiltering=trust['SidFilteringEnabled'],
                )
            elif direction in [2, 4]:
                props = dict(
                    target=identifier,
                    source=trust['TargetDomainSid'],
                    trusttype=trust_map[trust_type],
                    transitive=trust['IsTransitive'],
                    sidfiltering=trust['SidFilteringEnabled'],
                )
            else:
                logging.error(
                    "Could not determine direction of trust... direction: %s", direction)
                continue
            await tx.run(query, props=props)

    if 'ChildObjects' in domain and domain['ChildObjects']:
        targets = domain['ChildObjects']
        for target in targets:
            query = build_add_edge_query(
                'Domain', target['ObjectType'], 'Contains', '{isacl: false}')
            await tx.run(query, props=dict(source=identifier, target=target['ObjectIdentifier']))

    if 'Links' in domain and domain['Links']:
        query = build_add_edge_query(
            'GPO', 'OU', 'GPLink', '{isacl: false, enforced: prop.enforced}')
        for gpo in domain['Links']:
            await tx.run(
                query,
                props=dict(source=gpo['GUID'].upper(), target=identifier, enforced=gpo['IsEnforced'])
            )
    options = [
        ('LocalAdmins', 'AdminTo'),
        ('PSRemoteUsers', 'CanPSRemote'),
        ('DcomUsers', 'ExecuteDCOM'),
        ('RemoteDesktopUsers', 'CanRDP'),
    ]

    if 'GPOChanges' in domain and domain['GPOChanges']:
        gpo_changes = domain['GPOChanges']
        affected_computers = gpo_changes['AffectedComputers']
        for option, edge_name in options:
            if option in gpo_changes and gpo_changes[option]:
                targets = gpo_changes[option]
                for target in targets:
                    query = build_add_edge_query(
                        target['ObjectType'], 'Computer', edge_name, '{isacl: false, fromgpo: true}')
                    for computer in affected_computers:
                        await tx.run(query, props=dict(source=computer['ObjectIdentifier'], target=target['ObjectIdentifier']))


async def parse_container(tx: neo4j.Transaction, container: dict):
    """Parse a Container object.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j session
        container {dict} -- Single container object from the bloodhound json.
    """
    identifier = container['ObjectIdentifier']
    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:Container SET n += prop.map'
    props = {'map': container['Properties'], 'source': identifier}

    await tx.run(property_query, props=props)

    if 'Aces' in container and container['Aces'] is not None:
        await process_ace_list(container['Aces'], identifier, "Container", tx)

    if 'ChildObjects' in container and container['ChildObjects']:
        targets = container['ChildObjects']
        for target in targets:
            query = build_add_edge_query(
                'Container', target['ObjectType'], 'Contains', '{isacl: false}')
            await tx.run(query, props=dict(source=identifier, target=target['ObjectIdentifier']))


async def parse_zipfile(filename: str, driver: neo4j.Driver):
    """Parse a bloodhound zip file.

    Arguments:
        filename {str} -- ZIP filename to parse.
        driver {neo4j.GraphDatabase} -- driver to connect to neo4j.
    """
    with ZipFile(filename) as zip_file:
        all_files = sorted(zip_file.namelist())
        keywords = ['domain', 'group', 'container',
                    'gpo', 'ous', 'user', 'computer']
        mapping = {index: file for index, keyword in enumerate(
            keywords) for file in all_files if keyword in file}
        files = [mapping[i] for i in range(len(keywords)) if i in mapping]
        for file in files:
            if 'computer' not in file:
                continue
            if not file.endswith('.json'):
                logging.info(
                    "File does not appear to be JSON, skipping: %s", file)
                continue

            with NamedTemporaryFile(suffix=basename(file)) as temp:
                temp.write(zip_file.read(file))
                temp.flush()
                await parse_file(temp.name, driver)


async def parse_file(filename: str, driver: neo4j.AsyncDriver):
    """Parse a bloodhound file.

    Arguments:
        filename {str} -- JSON filename to parse.
        driver {neo4j.GraphDatabase} -- driver to connect to neo4j.
    """
    logging.info("Parsing bloodhound file: %s", filename)

    if filename.endswith('.zip'):
        logging.info(
            "File appears to be a zip file, importing all containing JSON files..")
        await parse_zipfile(filename, driver)
        return

    with codecs.open(filename, 'r', encoding='utf-8-sig') as f:
        meta = ijson.items(f, 'meta')
        for o in meta:
            obj_type = o['type']
            total = o['count']

    parsing_map = {
        'domains': parse_domain,
        'computers': parse_computer,
        'containers': parse_container,
        'users': parse_user,
        'groups': parse_group,
        'gpos': parse_gpo,
        'ous': parse_ou,
    }

    parse_function = None
    try:
        parse_function = parsing_map[obj_type]
    except KeyError:
        logging.error(
            "Parsing function for object type: %s was not found.", obj_type)
        return

    async with driver.session() as session:
        ten_percent = total // 10 if total > 10 else 1
        count = 0
        f = codecs.open(filename, 'r', encoding='utf-8-sig')
        objs = ijson.items(f, 'data.item')
        for entry in objs:
            try:
                await session.write_transaction(parse_function, entry)
                count = count + 1
            except neo4j.exceptions.ConstraintError as e:
                print(e)
            if count % ten_percent == 0:
                logging.info("Parsed %d out of %d records in %s.",
                             count, total, filename)

        if parse_function == parse_group:
            for object in OBJECT_GET_CHANGE:
                object_tree = build_tree(object, GROUP_MAPPING)
                for x in flatten_tree_to_list(object_tree):
                    if x not in OBJECT_GET_CHANGE:
                        OBJECT_GET_CHANGE.append(x)

            for object in OBJECT_GET_CHANGE_ALL:
                object_tree = build_tree(object, GROUP_MAPPING)
                for x in flatten_tree_to_list(object_tree):
                    if x not in OBJECT_GET_CHANGE_ALL:
                        OBJECT_GET_CHANGE_ALL.append(x)
            ten_percent = total // 10 if total > 10 else 1
            count = 0
            f = codecs.open(filename, 'r', encoding='utf-8-sig')
            objs = ijson.items(f, 'data.item')
            for entry in objs:
                ten_percent = ten_percent * 2
                try:
                    await session.write_transaction(parse_group2, entry)
                    count = count + 1
                except neo4j.exceptions.ConstraintError as e:
                    print(e)
                if count % ten_percent == 0:
                    logging.info("Parsed %d out of %d records in %s.",
                                 count, total, filename)

    f.close()
    logging.info("Completed file: %s", filename)
