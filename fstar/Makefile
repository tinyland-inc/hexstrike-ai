FSTAR ?= fstar.exe
FSTAR_FLAGS = --cache_dir cache --odir out

MODULES = Hexstrike.Types Hexstrike.Policy Hexstrike.Sanitize Hexstrike.Audit Hexstrike.Dispatch

SRC = $(addsuffix .fst,$(MODULES))
CHECKED = $(addprefix cache/,$(addsuffix .fst.checked,$(MODULES)))
EXTRACTED = $(addprefix out/,$(addsuffix .ml,$(subst .,_,$(MODULES))))

.PHONY: verify extract clean

verify: $(CHECKED)
	@echo ":: all F* modules verified"

extract: verify $(EXTRACTED)
	@echo ":: F* -> OCaml extraction complete"

cache/%.fst.checked: %.fst | cache
	$(FSTAR) $(FSTAR_FLAGS) $<

out/Hexstrike_%.ml: Hexstrike.%.fst | out
	$(FSTAR) $(FSTAR_FLAGS) --codegen OCaml $<

cache:
	mkdir -p cache

out:
	mkdir -p out

clean:
	rm -rf cache out *.checked
