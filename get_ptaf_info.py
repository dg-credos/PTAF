"""
скрипт делает следующее:
* подключается к REST API
* собирает данные о правилах защиты приложений
* преобразует полученные данные в текстовое представление
* сохраняет текстовое представление в файлы
** названия файлов формируются по шаблону "{policy_name}_{policy_id}.txt"
* можно отдельно выгрузить только переопределенные правила, задав only_overrided=True
** с помощью параметра postfix можно сохранить такие правила в отдельные файлы
** названия файлов формируются по шаблону "{policy_name}_{policy_id}{postfix}.txt"
*** например, postfix='_overrided' -> 'AppPolicy_GUID_overrided.txt'
* аналогично собираются и выгружаются данные о шаблонах политик защиты приложений

файлы сохраняются в папки по пути './data/polices' и './data/templates', для политик и шаблонов соответственно
пути можно изменить в настройках
!!! важно: файлы при сохранении перезаписываются без подтверждения
"""


import requests
import json


# отключение спама ошибок о "неправильном сертификате"
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# адрес MGMT PTAF и данные для входа
# у/з должна иметь права просмотра всех данных, которые собирает
# base_url = 'https://FQDN'
# session_auth = {
# 	'username': 'audit',
# 	'password': 'password',
# 	'fingerprint': 'test_2025',
# }

from config import base_url
from config import session_auth

pathroot_polices = './data/polices'
pathroot_templates = './data/templates'


def check_status_code(status_code: int, ok_code: int | list = 200) -> None | str:
	"""
	проверяется статус веб-запроса
	статус считается успешным, если код находится в списке ok_code
		возвращается None
	иначе возвращается текст ошибки
	"""
	if not isinstance(ok_code, list):
		ok_code = [ok_code]
	if status_code in ok_code:
		return None

	match status_code:
		case 500:
			# 500 (Internal server errorTraceback) — внутренняя ошибка сервера.
			_err = f'Internal server errorTraceback: {status_code = }'
		case 401:
			# 401 (InvalidToken) — неверный токен аутентификации;
			_err = f'InvalidToken: {status_code = }'
		case 403:
			# 403 (Forbidden) — доступ запрещен;
			_err = f'Forbidden: {status_code = }'
		case 404:
			# 404 (reference_not_exist) — указанный ресурс не найден или не существует.
			_err = f'reference_not_exist: {status_code = }'
		case 422:
			# 422 (incorrect_credentials) — ошибка аутентификации или семантически некорректный запрос;
			# 422 (invalid_token) — неверный токен аутентификации, отпечаток клиента или идентификатор изолированного пространства, а также семантически некорректный запрос;
			_err = f'incorrect_credentials | invalid_token: {status_code = }'
		case _:
			_err = f'Unknown error: {status_code = }'

	return _err


def connect_to_rest_api(base_url:str, session_auth: dict, ok_code: int | list = 200) -> tuple[requests.Session, str]:
	"""
	подключения к REST API по переданному адресу системы с переданными учетными данными
	после успешного открытия сессии, в заголовки добавляется токен аутентификации
	возвращается сессия и адрес API
	"""

	api_url = f'{base_url}/api/ptaf/v4'
	auth_url = f'{api_url}/auth/refresh_tokens'

	session = requests.Session()
	result = session.request('POST', url = auth_url, json = session_auth, verify=False)
	status_code = result.status_code

	# print(f'{result_status = }')
	if _err := check_status_code(status_code, ok_code = ok_code):
		raise RuntimeError(_err)

	content_json = json.loads(result.content)

	auth_access_token = content_json.get("access_token", None)
	if auth_access_token is None:
		_err = f'Auth token is None:\n{auth_access_token = }\n{content_json = }'
		raise RuntimeError(_err)

	session.headers['Authorization'] = f'Bearer {auth_access_token}'

	return session, api_url


def get_api_url_content(session: requests.Session, api_url: str, ok_code: int | list = 200) -> requests.Response:
	req = session.get(url = api_url, verify=False)
	result_status = req.status_code
	if _err := check_status_code(result_status, ok_code = ok_code):
		raise RuntimeError(_err)
	return req


def get_api_url_content_as_json(session: requests.Session, api_url: str, ok_code: int | list = 200) -> dict:
	req = get_api_url_content(session=session, api_url=api_url, ok_code=ok_code)
	content_json = json.loads(req.content)
	return content_json


def get_about_info(session: requests.Session, api_url: str, print_info: bool = False) -> dict:
	about_url = f'{api_url}/about/versions'
	about_json = get_api_url_content_as_json(session=session, api_url=about_url)

	if print_info:
		print(f'{about_json = }')

	return about_json


def get_application_polices(session: requests.Session, api_url: str, print_info: bool = False) -> dict:
	policy_url = f'{api_url}/config/policies'
	policy_json = get_api_url_content_as_json(session=session, api_url=policy_url)
	polices = policy_json['items']

	if print_info:
		print(f'{len(polices) = }')
		print(f'{policy_json = }')

	return polices


def get_application_policy_rules(session: requests.Session, api_url: str, policy_id: str, print_info: bool = False) -> dict:
	policy_rules_url = f'{api_url}/config/policies/{policy_id}/rules'
	if print_info:
		print(f'{policy_rules_url = }')

	policy_rules_json = get_api_url_content_as_json(session=session, api_url=policy_rules_url)

	return policy_rules_json['items']


def get_application_policy_rule_info(session: requests.Session, api_url: str, policy_id: str, rule_id: str, print_info: bool = False) -> dict:
	rule_info_url = f'{api_url}/config/policies/{policy_id}/rules/{rule_id}'
	rule_info = get_api_url_content_as_json(session=session, api_url=rule_info_url)
	return rule_info


def get_info_application_polices(session: requests.Session, api_url: str, filter_by_id: str = None, print_info: bool = False) -> dict:
	"""
	получение информации о всех политиках защиты приложений
	если передан filter_by_id, то запрашивается информация только по этой политике

	возвращается словарь "политика:правила" в формате:
		ключ: str:{policy_name}_{policy_id}
		значение: list:перечень json с информацией о правилах
	"""
	application_polices = get_application_polices(session=session, api_url=api_url, print_info=False)
	print(f'{len(application_polices) = }')

	applications_info = dict()

	for application_policy in application_polices:
		rules_info = []
		policy_id = application_policy['id']
		if filter_by_id is not None and policy_id != filter_by_id:
			continue
		policy_name = application_policy['name']
		print(f'{policy_name = }, {policy_id = }')

		application_policy_rules = get_application_policy_rules(
			session=session, api_url=api_url,
			policy_id=policy_id, print_info=True,
		)

		for application_policy_rule in application_policy_rules:
			rule_id = application_policy_rule['id']
			rule_name = application_policy_rule['name']
			rule_enabled = application_policy_rule['enabled']
			# print(f'{rule_name = }, {rule_id = }')
			rule_info = get_application_policy_rule_info(
				session=session, api_url=api_url,
				policy_id=policy_id, rule_id=rule_id,
				print_info=True,
			)
			if print_info:
				if rule_info['has_overrides'] != False:
					rule_desc = f'Overrided'
					print(f'{rule_desc}\t{rule_name}\t{rule_enabled}')
					# print(f'	{application_policy_rule = }')
					# print(f'	{rule_info = }')

			rule_info = {
				'parent_name': policy_name,
				'parent_id': policy_id,
				'rule_name': rule_name,
				'rule_id': rule_id,
				'rule_enabled': rule_enabled,
				'rule_has_overrides': rule_info.get('has_overrides', True),
				'rule_variables': rule_info.get('variables', {}),
				'template_id': rule_info.get('policy_template_id', ''),
				'template_type': rule_info.get('policy_template_type', ''),
				'phase': rule_info.get('phase', ''),
				'is_system': rule_info.get('is_system', ''),
				'event': rule_info.get('event', ''),
				'actions': rule_info.get('actions', ''),
			}
			rules_info.append(rule_info)

		applications_info[f'{policy_name}_{policy_id}'] = rules_info

	return applications_info


def get_policy_templates(session: requests.Session, api_url: str, print_info: bool = False) -> dict:
	template_url = f'{api_url}/config/policies/templates/user'
	template_json = get_api_url_content_as_json(session=session, api_url=template_url)
	templates = template_json['items']

	if print_info:
		print(f'{len(templates) = }')
		print(f'{template_json = }')

	return templates


def get_policy_template_rules(session: requests.Session, api_url: str, template_id: str, print_info: bool = False) -> dict:
	template_rules_url = f'{api_url}/config/policies/templates/user/{template_id}/rules'
	if print_info:
		print(f'{template_rules_url = }')

	template_rules_json = get_api_url_content_as_json(session=session, api_url=template_rules_url)

	return template_rules_json['items']


def get_policy_template_rule_info(session: requests.Session, api_url: str, template_id: str, rule_id: str, print_info: bool = False) -> dict:
	rule_info_url = f'{api_url}/config/policies/templates/user/{template_id}/rules/{rule_id}'
	rule_info = get_api_url_content_as_json(session=session, api_url=rule_info_url)
	return rule_info


def get_info_policy_templates(session: requests.Session, api_url: str, filter_by_id: str = None, print_info: bool = False) -> dict:
	policy_templates = get_policy_templates(session=session, api_url=api_url, print_info=False)
	print(f'{len(policy_templates) = }')

	templates_info = dict()

	for policy_template in policy_templates:
		rules_info = []
		template_id = policy_template['id']
		if filter_by_id is not None and template_id != filter_by_id:
			continue
		template_name = policy_template['name']
		print(f'{template_name = }, {template_id = }')

		policy_template_rules = get_policy_template_rules(
			session=session, api_url=api_url,
			template_id=template_id, print_info=True,
		)

		for policy_template_rule in policy_template_rules:
			rule_id = policy_template_rule['id']
			rule_name = policy_template_rule['name']
			rule_enabled = policy_template_rule['enabled']
			# print(f'{rule_name = }, {rule_id = }')
			rule_info = get_policy_template_rule_info(
				session=session, api_url=api_url,
				template_id=template_id, rule_id=rule_id,
				print_info=True,
			)
			if print_info:
				if rule_info['has_overrides'] != False:
					rule_desc = f'Overrided'
					print(f'{rule_desc}\t{rule_name}\t{rule_enabled}')
					# print(f'	{policy_template_rule = }')
					# print(f'	{rule_info = }')

			rule_info = {
				'parent_name': template_name,
				'parent_id': template_id,
				'rule_name': rule_name,
				'rule_id': rule_id,
				'rule_enabled': rule_enabled,
				'rule_has_overrides': rule_info['has_overrides'],
				'rule_variables': rule_info.get('variables', None),
				'policy_template_id': rule_info['policy_template_id'],
				'policy_template_type': rule_info['policy_template_type'],
			}
			rules_info.append(rule_info)

		templates_info[f'{template_name}_{template_id}'] = rules_info

	return templates_info


def get_actions_user_friendly(session: requests.Session, api_url: str, print_info: bool = False) -> dict:
	actions_url = f'{api_url}/config/actions'
	actions_json = get_api_url_content_as_json(session=session, api_url=actions_url)
	actions = actions_json['items']

	if print_info:
		print(f'{len(actions) = }')
		print(f'{actions_json = }')

	# actions_user_friendly = {}
	# for action in actions:
	# 	actions_user_friendly[action['id']] = action['name']
	actions_user_friendly = {action['id'] : action['name'] for action in actions}

	return actions_user_friendly


def get_classifiers_user_friendly(session: requests.Session, api_url: str, print_info: bool = False) -> dict:
	classifiers_url = f'{api_url}/config/classifiers'
	classifiers_json = get_api_url_content_as_json(session=session, api_url=classifiers_url)
	classifiers = classifiers_json['items']

	if print_info:
		print(f'{len(classifiers) = }')
		print(f'{classifiers_json = }')

	# classifiers_user_friendly = {}
	# for classifier in classifiers:
	# 	classifiers_user_friendly[classifier['id']] = classifier['name']
	classifiers_user_friendly = {classifier['id'] : classifier['name'] for classifier in classifiers}

	return classifiers_user_friendly


def convert_rules_info_to_text(
		rules_info: dict,
		only_overrided: bool = False,
		delimiter: str = '\t',
		skip_columns: list = None,
		columns_names: dict = None,
		actions: dict = None,
		classifiers: dict = None,
	) -> dict:
	"""
	получает словарь "политика:данные о правилах"
	возвращает текстовое представление данных
	при преобразовании в текст, названия полей заменяются на те, что переданы в словаре columns_names

	возвращает словарь "app_id:текст"
		где, app_id берется из ключей словаря rules_info
	"""
	app_info = dict()
	for app_id, rules_info in rules_info.items():
		rule_info_keys = rules_info[0].keys()

		skip_keys = [] if skip_columns is None else skip_columns
		skip_keys += ['rule_variables']

		columns_names = columns_names or dict()
		columns_names = {key: columns_names.get(key, key) for key in rule_info_keys}

		rules_text = [delimiter.join([key for key in rule_info_keys if key not in skip_keys])]

		def replace_guid_in_rule_info(rule_info: dict, key: str) -> str:
			rule_value = rule_info.get(key, {})
			rule_text = str(rule_value)
			match key:
				case 'actions':
					for key, value in actions.items():
						rule_text = rule_text.replace(key, f'{value}\t{key}')
				case 'event':
					for key, value in classifiers.items():
						rule_text = rule_text.replace(key, f'{value}\t{key}')
					# classifications = rule_value.get('classifications', None)
					# if isinstance(classifications, dict):
					# 	pass
				case _:
					pass
			return rule_text

		def get_rule_info_value(rule_info: dict, key: str = None) -> str:
			# rule_info_lines = [delimiter.join([str(rule_info.get(key, '')) for key in rule_info_keys if key not in skip_keys])]
			rule_info_lines = [f'{columns_names[key]}: {replace_guid_in_rule_info(rule_info, key)}' for key in rule_info_keys if key not in skip_keys]

			rule_variables: dict | None = rule_info.get('rule_variables', None)
			if rule_variables is not None:
				rule_info_lines += [columns_names['rule_variables'] + ':']
				rule_info_lines += [f'{key} = {value}' for key, value in rule_variables.items()]

			rule_info_lines += ['']
			return '\n'.join(rule_info_lines)

		if only_overrided:
			# rules_text += [delimiter.join([get_rule_info_value(rule_info, key) for key in rule_info_keys])
			# 	for rule_info in rules_info if rule_info['rule_has_overrides']]
			rules_text += [get_rule_info_value(rule_info)
				for rule_info in rules_info if rule_info['rule_has_overrides']]
		else:
			# rules_text += [delimiter.join([get_rule_info_value(rule_info, key) for key in rule_info_keys])
			# 	for rule_info in rules_info]
			rules_text += [get_rule_info_value(rule_info)
				for rule_info in rules_info]

		rules_text = '\n'.join(rules_text)
		app_info[app_id] = rules_text

	return app_info


def save_text_info_to_files(path: str, data: dict, postfix: str = None, encoding: str = 'utf-8'):
	postfix = '.txt' if postfix is None else f'{postfix}.txt'
	for filename, filedata in data.items():
		with open(f'{path}/{filename}{postfix}', 'w', encoding=encoding) as out:
			out.write(filedata)


def gather_polices_info(session: requests.Session, api_url: str, pathroot: str, filter_by_id: str = None, actions: dict = None, classifiers: dict = None):
	rule_columns_names = {
		'parent_id': 'Индентификатор приложения',
		'parent_name': 'Название приложения',
		'rule_name': 'Название правила',
		'rule_id': 'Идентификатор правила',
		'rule_enabled': 'Включено',
		'rule_has_overrides': 'Переопределено',
		'rule_variables': 'Параметры правила',
		'template_id': 'Индентификатор шаблона',
		'template_type': 'Тип шаблона',
		'phase': 'Фаза',
		'is_system': 'Системное правило',
		'event': 'Событие',
		'actions': 'Действия',
	}

	polices_rules_info = get_info_application_polices(
		session=session, api_url=api_url,
		filter_by_id = filter_by_id,
		print_info=False,
	)

	rules_text = convert_rules_info_to_text(
		rules_info=polices_rules_info,
		# skip_columns=['parent_id', 'parent_name'],
		columns_names=rule_columns_names,
		actions=actions,
		classifiers=classifiers,
	)
	save_text_info_to_files(path=pathroot, data=rules_text)

	rules_text = convert_rules_info_to_text(
		rules_info=polices_rules_info,
		only_overrided=True,
		# skip_columns=['parent_id', 'parent_name'],
		columns_names=rule_columns_names,
		actions=actions,
		classifiers=classifiers,
	)
	save_text_info_to_files(path=pathroot, data=rules_text, postfix='__overrides')


def gather_templates_info(session: requests.Session, api_url: str, pathroot: str, filter_by_id: str = None, actions: dict = None, classifiers: dict = None):
	rule_columns_names = {
		'parent_id': 'Индентификатор шаблона',
		'parent_name': 'Название шаблона',
		'rule_name': 'Название правила',
		'rule_id': 'Идентификатор правила',
		'rule_enabled': 'Включено',
		'rule_has_overrides': 'Переопределено',
		'rule_variables': 'Параметры правила',
		'policy_template_id': 'Идентификатор шаблона политики безопасности',
		'policy_template_type': 'Тип шаблона политики безопасности',
		'phase': 'Фаза',
		'is_system': 'Системное правило',
		'event': 'Событие',
		'actions': 'Действия',
	}

	templates_rules_info = get_info_policy_templates(
		session=session, api_url=api_url,
		filter_by_id = filter_by_id,
		print_info=False,
	)

	rules_text = convert_rules_info_to_text(
		rules_info=templates_rules_info,
		# skip_columns=['parent_id', 'parent_name'],
		columns_names=rule_columns_names,
		actions=actions,
		classifiers=classifiers,
	)
	save_text_info_to_files(path=pathroot, data=rules_text)

	rules_text = convert_rules_info_to_text(
		rules_info=templates_rules_info,
		only_overrided=True,
		# skip_columns=['parent_id', 'parent_name'],
		columns_names=rule_columns_names,
		actions=actions,
		classifiers=classifiers,
	)
	save_text_info_to_files(path=pathroot, data=rules_text, postfix='__overrides')


def get_ptaf_info():
	session, api_url = connect_to_rest_api(base_url=base_url, session_auth=session_auth, ok_code=201)
	print(f'{session.headers = }')

	system_about = get_about_info(session=session, api_url=api_url, print_info=False)
	print(f'{system_about = }')


	actions_user_friendly = get_actions_user_friendly(session=session, api_url=api_url)
	classifiers_user_friendly = get_classifiers_user_friendly(session=session, api_url=api_url)

	gather_polices_info(
		session=session, api_url=api_url,
		pathroot=pathroot_polices,
		# filter_by_id = 'c8e2d0e5-aa70-445a-beea-f809e5d203f1', # 1c-web
		# filter_by_id = '7e28387e-7f62-468c-82b9-025d128ed216', # bitrix
		actions=actions_user_friendly,
		classifiers=classifiers_user_friendly,
	)

	gather_templates_info(
		session=session, api_url=api_url,
		pathroot=pathroot_templates,
		# filter_by_id='7c749ae1-f96b-432a-bfe7-81006dd570b6', # 'Bitrix (user)'
		actions=actions_user_friendly,
		classifiers=classifiers_user_friendly,
	)


if __name__ == '__main__':
	get_ptaf_info()

