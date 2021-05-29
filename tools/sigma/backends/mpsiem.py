import re

from sigma.parser.modifiers.base import SigmaTypeModifier
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier
from .base import SingleTextQueryBackend
from sigma.backends.exceptions import NotSupportedError
#from sigma.parser.condition import condition_map


def get_process_name_from_image_value(value):
    rex = re.compile('^\*(\\\\)?([\w\-.]+\.exe)(\*)?$')
    result = rex.search(value)
    if result is None:
        return None
    else:
        name_pattern = result.group(2)
        if result.group(1) is None:
            name_pattern = "*" + name_pattern
        if result.group(3) is not None:
            name_pattern = name_pattern + "*"
        return name_pattern


def split_name_path_value(value):
    rex = re.compile('^(\*\\\\.*)\\\\([\w\-.]+\.exe)$')
    result = rex.search(value)
    if result is None:
        return None, None
    else:
        return result.group(1), result.group(2)


class MPSiemQueryBackend(SingleTextQueryBackend):
    """Converts Sigma rule into MP SIEM PDQL query string. Only searches, no aggregations."""
    identifier = "mpsiem"
    active = True
    default_config = ["mpsiem"]

    # escape
    #  " -> \"
    #  \ -> \\
    # \\ -> \\
    reEscape = re.compile(r'(["\\])')
    andToken = " AND "
    orToken = " OR "
    notToken = "NOT "
    equalExpression = "%s = \"%s\""
    subExpression = "%s"
    valueExpression = "%s"
    nullExpression = "%s = null"
    notNullExpression = "%s != null"
    mapExpression = "%s MATCH \"%s\""
    startswithExpression = "%s STARTSWITH \"%s\""
    endswithExpression = "%s ENDSWITH \"%s\""
    containsExpressoin = "%s CONTAINS \"%s\""

    def generate(self, sigma_rule):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        for parsed_conditions in sigma_rule.condparsed:
            query = self.generateQuery(parsed_conditions)
            before = self.generateBefore(parsed_conditions)
            after = self.generateAfter(parsed_conditions)

            result = ""
            if before is not None:
                result = before
            if query is not None:
                result += query
            if after is not None:
                result += after
            return result

    def generateMapItemListNode(self, fieldname, value):
        result = []
        for item in value:
            result.append(self.generateMapItemNode((fieldname, item)))
        return "(%s)" % self.orToken.join(result)

    '''
    def generateEqualValueNode(self, node):
        result = super().generateValueNode(node)
        if result == "" or result.isspace():
            return '""'
        else:
            if "*" in result:
                raise Exception("Invalid value in equal operation")

            result = result.replace("\\\\", "\\")
            result = result.replace("\\=", "=")
            return result.replace("\\:", ":")
    '''

    def generateANDNode(self, node):
        andExpr = super().generateANDNode(node)
        if andExpr is not None:
            return "(%s)" % andExpr 
        else:
            return None

    def generateORNode(self, node):
        orExpr = super().generateORNode(node)
        if orExpr is not None:
            return "(%s)" % orExpr 
        else:
            return None

    def fieldNameMapping(self, fieldname, value):
        """
        Alter field names depending on the value(s). Backends may use this method to perform a final transformation of the field name
        in addition to the field mapping defined in the conversion configuration. The field name passed to this method was already
        transformed from the original name given in the Sigma rule.
        """
        if fieldname == "Image":
            executable_name = get_process_name_from_image_value(value)
            if executable_name is None:
                path, name = split_name_path_value(value)
                if path is not None:
                    return [{"fieldname": "object.path", "value": path},
                            {"fieldname": "object.name", "value": name}]
                else:
                    return {"fieldname": "object.path", "value": value}
            else:
                return {"fieldname": "object.name", "value": executable_name}

        if fieldname == "ParentImage":
            executable_name = get_process_name_from_image_value(value)
            if executable_name is None:
                path, name = split_name_path_value(value)
                if path is not None:
                    return [{"fieldname": "datafield3", "value": path},
                            {"filedname": "datafield4", "value": name}]
                else:
                    return {"fieldname": "datafield3", "value": value}
            else:
                return {"fieldname": "datafield4", "value": executable_name}
        if fieldname == "EventType":
            if "Delete" in value:
                return {"fieldname": "action", "value": "remove"}
            if "Create" in value:
                return {"fieldname": "action", "value": "create"}
            if "SetValue" in value:
                return {"fieldname": "action", "value": "modify"}
            if "RenameKey" in value:
                return {"fieldname": "action", "value": "modify"}

        return {"fieldname": fieldname, "value": value}

    def generateMapItemNode(self, node):
        fieldname, value = node

        if fieldname == "msgid" and value == 1121:
            raise NotSupportedError("Attack Surface Reduction events unsupported by MPSIEM")

        if fieldname == "ObjectServer" and value == "DS":
            return self.equalExpression % ("object", "ds_object")
        if type(value) == int:
            return self.equalExpression % (fieldname, self.generateValueNode(value))
        if type(value) == str:
            if fieldname.lower() in ["imphash", "sha1", "sha256", "md5"]:
                #hash_algorithm = fieldname.upper()
                return "(object.hash contains \"%s\" )" % (value)

            mapping_result = self.fieldNameMapping(fieldname, value)
            if type(mapping_result) == dict:
                transformed_fieldname = mapping_result["fieldname"]
                transformed_value = mapping_result["value"]
                if "*" not in transformed_value:
                    #return self.equalExpression % (transformed_fieldname, self.generateEqualValueNode(transformed_value))
                    return self.equalExpression % (transformed_fieldname, self.generateValueNode(transformed_value))
                else:
                    if transformed_value.endswith('*') and transformed_value.startswith('*'):
                        return self.containsExpressoin % (transformed_fieldname, transformed_value.strip('*').replace('\\','\\\\'))
                    else:
                        if transformed_value.endswith('*'):
                            if "\*" in transformed_value:
                                return self.startswithExpression % (transformed_fieldname, transformed_value.replace('\*', '').replace('\\','\\\\'))
                            else:
                                return self.startswithExpression % (transformed_fieldname, transformed_value.strip('*').replace('\\','\\\\'))
                        elif transformed_value.startswith('*'):
                            return self.endswithExpression % (transformed_fieldname, transformed_value.strip('*').replace('\\','\\\\'))
                        else:
                            raise Exception("Unsupported pattern format!") 
                            #return self.mapExpression % (transformed_fieldname, self.generateValueNode(transformed_value))

            elif type(mapping_result) == list:
                path_field = mapping_result[0]["fieldname"]
                path_value = mapping_result[0]["value"]
                name_field = mapping_result[1]["fieldname"]
                name_value = mapping_result[1]["value"]
                return "((%s match \"%s\") AND (%s = \"%s\"))" % (path_field, self.generateValueNode(path_value), name_field, name_value)
            else:
                raise Exception("Unexpected custom mapping procedure result!")
        elif type(value) == list:
            return self.generateMapItemListNode(fieldname, value)
        elif isinstance(value, SigmaTypeModifier):
            return self.generateMapItemTypedNode(fieldname, value)
        elif value is None:
            if fieldname.lower() in ["imphash", "sha1", "sha256", "md5"]:
                return "(NOT (object.hash contains \"%s\"))" % fieldname.upper()
            return self.nullExpression % (fieldname,)
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemTypedNode(self, fieldname, value):
        return self.mapExpression % (fieldname, self.generateValueNode(value))

    def generateValueNode(self, node):
        if type(node) is str:
            result = super().generateValueNode(node)
            if not result.strip():
                return '""'
            return result
        return super().generateValueNode(node)
