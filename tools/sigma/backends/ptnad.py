import re

from sigma.parser.modifiers.base import SigmaTypeModifier
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier
from .base import SingleTextQueryBackend
from sigma.backends.exceptions import NotSupportedError
#from sigma.parser.condition import condition_map


class PTNADQueryBackend(SingleTextQueryBackend):
    """Converts Sigma rule into PT NAD query string. Only searches, no aggregations."""
    identifier = "ptnad"
    active = True
    default_config = ["ptnad"]
    andToken = " AND "
    orToken = " OR "
    notToken = "NOT "
    equalExpression = "%s == \"%s\""
    subExpression = "(%s)"
    valueExpression = "%s"
    typedValueExpression = {
        SigmaRegularExpressionModifier: "/%s/"
    }
    nullExpression = "!%s"
    notNullExpression = "%s"
    mapExpression = "%s ~ \"%s\""
    containsExpressoin = "%s ~ \"*%s*\""

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

    def generateAggregation(self, agg):
        pass

    def generateMapItemListNode(self, fieldname, value):
        result = []
        for item in value:
            result.append(self.generateMapItemNode((fieldname, item)))

        return "(%s)" % self.orToken.join(result)

    def fieldNameMapping(self, fieldname, value):
        """
        Alter field names depending on the value(s). Backends may use this method to perform a final transformation of the field name
        in addition to the field mapping defined in the conversion configuration. The field name passed to this method was already
        transformed from the original name given in the Sigma rule.
        """
        return {"fieldname": fieldname, "value": value}

    def generateMapItemNode(self, node):
        fieldname, value = node
        if type(value) == int:
            return self.equalExpression % (fieldname, self.generateValueNode(value))
        if type(value) == str:
            mapping_result = self.fieldNameMapping(fieldname, value)
            if type(mapping_result) == dict:
                transformed_fieldname = mapping_result["fieldname"]
                transformed_value = mapping_result["value"]
                if "*" not in transformed_value:
                    return self.equalExpression % (transformed_fieldname, transformed_value)
                else:
                    if transformed_value.endswith('*') and transformed_value.startswith('*'):
                        return self.containsExpressoin % (transformed_fieldname, transformed_value.strip('*'))
                    else:
                        return self.mapExpression % (transformed_fieldname, transformed_value)
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
            return self.nullExpression % (fieldname,)
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemTypedNode(self, fieldname, value):
        return self.mapExpression % (fieldname, value)

    def generateValueNode(self, node):
        return super().generateValueNode(node)
