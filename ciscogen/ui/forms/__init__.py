"""Section forms.  Each form binds directly into project.data[section]."""

from .system import SystemForm
from .vrf import VrfForm
from .interfaces import InterfacesForm
from .vlans import VlansForm
from .layer3 import Layer3Form
from .ipv6 import Ipv6Form
from .dhcp import DhcpForm
from .nat import NatForm
from .acls import AclsForm
from .routing import RoutingForm
from .tunnels import TunnelsForm
from .dmvpn import DmvpnForm
from .ipsla import IpslaForm
from .zbf import ZbfForm
from .qos import QosForm
from .ha import HaForm
from .security import SecurityForm
from .misc import MiscForm
from .custom_cli import CustomCliForm

FORM_CLASSES = {
    "system": SystemForm,
    "vrf": VrfForm,
    "interfaces": InterfacesForm,
    "vlans": VlansForm,
    "layer3": Layer3Form,
    "ipv6": Ipv6Form,
    "dhcp": DhcpForm,
    "nat": NatForm,
    "acls": AclsForm,
    "routing": RoutingForm,
    "tunnels": TunnelsForm,
    "dmvpn": DmvpnForm,
    "ipsla": IpslaForm,
    "zbf": ZbfForm,
    "qos": QosForm,
    "ha": HaForm,
    "security": SecurityForm,
    "misc": MiscForm,
    "custom_cli": CustomCliForm,
}
