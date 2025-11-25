## This is under development

# kubectl-analyze

This project is aimed and creating a way to carry out analysis of kubernetes resources using configurable rules. 

Whilst some similar tools exist, they are usually working against the YAML configuration files which is a pretty good 
way of doing things. However in situations where you do not have access to the YAML files, this tool may be of use. 

```aiignore
kubectl analyze -r my-rules.json -n dev
kubectl analyze -n dev
```

A default set of rules is included in the kubectl-analyze-rules.json file. Although you can override this file with your own rules.

## Rules file

The rules file is a json file with aan array of rules. 

Each rule consists of

- name: A name for the rule
- description: A description of the rule, this is just for documentation
- resource: The resource type that rule is run against
- jsonpath: The jsonpath to the field that is checked
- operator: The operator to use for the check, for example ==, !=, >, <, >=, <=
- value: The value to compare against
- category: The category of the rule, for example networking, security, etc.
- severity: The severity of the rule, for example error, warning, info

The category and severity are just ways to organise the rules.