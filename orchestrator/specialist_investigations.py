"""Conservative investigation templates; planning never authorizes execution."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

Specialty = Literal['authorization', 'authentication', 'exposure', 'input_validation', 'business_logic']


class InvestigationRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    specialty: Specialty
    hypothesis: str = Field(min_length=1, max_length=2000)


# These are questions for a researcher, not instructions to execute requests.
TEMPLATES = {
    'authorization': {
        'prerequisites': ['Two researcher-controlled identities and a researcher-controlled object', 'Reviewed expected permissions and an in-scope approved request'],
        'minimum_test': 'Compare the object response for its owner and the other identity using separately approved observations.',
        'normal_result': 'The other identity receives only content permitted by the reviewed access policy.',
        'abnormal_result': 'The other identity receives meaningful object content contrary to the reviewed permission.',
        'disconfirming_evidence': 'The content is public or sharing permission explicitly permits access.',
        'required_capability': 'authenticated_http',
    },
    'authentication': {
        'prerequisites': ['Researcher-controlled account', 'Explicit permission for the intended session action and a reviewed expected outcome'],
        'minimum_test': 'Compare a protected resource with and without a valid controlled session.',
        'normal_result': 'Protected content is unavailable without the required session.',
        'abnormal_result': 'Meaningful protected content is accessible without the required session.',
        'disconfirming_evidence': 'The resource is intentionally public or the response contains no protected content.',
        'required_capability': 'authenticated_http',
    },
    'exposure': {
        'prerequisites': ['Controlled data or explicit authorization to inspect the data', 'Reviewed expectation of public and private content'],
        'minimum_test': 'Compare a bounded observed response with the documented visibility of its content.',
        'normal_result': 'The response contains only information intended for its audience.',
        'abnormal_result': 'The response contains meaningful private data disclosed outside its intended audience.',
        'disconfirming_evidence': 'The content is already public or explicitly intended for the recipient.',
        'required_capability': 'saved_evidence',
    },
    'input_validation': {
        'prerequisites': ['A reviewed bounded input profile', 'A controlled input and an explicitly permitted target action'],
        'minimum_test': 'Compare one benign baseline with one approved bounded input and inspect the resulting behavior.',
        'normal_result': 'Input is handled according to the documented boundary.',
        'abnormal_result': 'Evidence demonstrates a violation of the documented boundary.',
        'disconfirming_evidence': 'The response is expected validation or a generic error without demonstrated impact.',
        'required_capability': 'reviewed_input_profile',
    },
    'business_logic': {
        'prerequisites': ['Researcher-controlled accounts and objects', 'A human-reviewed invariant and authorized state change'],
        'minimum_test': 'Record the before and after state of the smallest controlled action and compare it to the invariant.',
        'normal_result': 'The invariant remains true after the action.',
        'abnormal_result': 'Evidence demonstrates the invariant was violated by the controlled action.',
        'disconfirming_evidence': 'The state change is explicitly allowed by the reviewed workflow.',
        'required_capability': 'reviewed_state_change',
    },
}


def investigation_capabilities(advertised: dict, scope: dict) -> dict:
    """A worker advertises execution; current lab scope must separately permit it."""
    def version(name):
        value = advertised.get(name)
        return type(value) is int and value == 1
    lab = scope.get('web_authenticated_replay') is True and not scope.get('program_policy')
    specialist = lab and scope.get('web_specialist_profiles') is True and version('specialist_http_version')
    return {'saved_evidence': True, 'authenticated_http': lab and version('authenticated_http_version'),
            'reviewed_input_profile': specialist, 'reviewed_state_change': specialist}


def plan_investigation(request: InvestigationRequest, capabilities: dict) -> dict:
    template = TEMPLATES[request.specialty]
    required = template['required_capability']
    available = capabilities.get(required) is True
    return {
        'specialty': request.specialty, 'hypothesis': request.hypothesis,
        **template,
        'stop_conditions': ['Stop on scope uncertainty, unexpected data, throttling, errors, or revoked permission.',
                            'Stop when sufficient bounded evidence has been collected.'],
        'status': 'requires_review' if available else 'blocked',
        'blocked_reasons': [] if available else [f'Required capability unavailable: {required}'],
        'reviewed_profile': {'input_validation': 'integer_query', 'business_logic': 'controlled_json_put'}.get(request.specialty),
        'limitations': ['Prerequisites and permissions require human verification; this plan does not authorize or execute tests.',
                        'A status code, version match, scanner label, or model confidence alone cannot confirm a finding.',
                        'Specialty execution is limited to one integer GET query or one scalar JSON PUT field on a recorded controlled-object lab resource.'],
    }
