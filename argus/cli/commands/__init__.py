# argus/cli/commands/__init__.py

from importlib import import_module
from types import ModuleType
from typing import List, Type, Set

# Subcommand modules (each must define __mixin_name__ = "<ClassName>")
_COMMAND_MODULES: List[str] = [
    ".browse",
    ".select",
    ".run",
    ".flow_control",
    ".info",
    ".favorites",
    ".utility",
    ".help",
    ".scan",
    ".session_cmd",
]

__all__ = ["COMMAND_MIXINS", "register_mixins"]

# Will hold the final unique mixin classes in import order.
COMMAND_MIXINS: List[Type] = []

# Internal: tracks unique identity of mixin classes we've added.
# Using fully-qualified "module.Class" avoids duplicates when modules are imported
# via different paths that point to the same class object.
_seen_mixin_keys: Set[str] = set()


def _add_mixin_once(mixin_cls: Type) -> None:
    """Append mixin_cls to COMMAND_MIXINS only if not already present (by fq name)."""
    key = f"{mixin_cls.__module__}.{mixin_cls.__name__}"
    if key not in _seen_mixin_keys:
        _seen_mixin_keys.add(key)
        COMMAND_MIXINS.append(mixin_cls)


for mod_name in _COMMAND_MODULES:
    mod: ModuleType = import_module(mod_name, package=__name__)

    try:
        mixin_attr_name = getattr(mod, "__mixin_name__")
        mixin_cls = getattr(mod, mixin_attr_name)
    except AttributeError as e:
        raise ImportError(
            f"Command module '{mod.__name__}' must define "
            f"__mixin_name__ and the referenced class."
        ) from e

    _add_mixin_once(mixin_cls)


def _unique(sequence: List[Type]) -> List[Type]:
    seen: Set[str] = set()
    out: List[Type] = []
    for cls in sequence:
        key = f"{cls.__module__}.{cls.__name__}"
        if key not in seen:
            seen.add(key)
            out.append(cls)
    return out


def register_mixins(base_cls: Type) -> Type:
    unique_mixins = _unique(COMMAND_MIXINS)
    name = f"{base_cls.__name__}With" + "".join(m.__name__ for m in unique_mixins)
    return type(name, tuple(unique_mixins) + (base_cls,), {})
