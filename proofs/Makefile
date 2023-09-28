src_files := $(wildcard *.pv)
res_files :=  $(src_files:%.pv=%.res)

all: $(res_files)

%.res: %.pv scrambledb.pvl
	@echo "=> Analysis: " $<
	@proverif -lib scrambledb $< > $@
	@grep -A100 -e 'Verification summary:' $@


.PHONY: clean
clean:
	rm -f $(wildcard *.res)
