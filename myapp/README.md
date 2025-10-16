# myapp PML Project

This is a SELinux policy project using Casbin PML.

## Files

- **model.conf**: PML model definition
- **policy.csv**: PML policy rules
- **output/**: Generated SELinux policy files

## Usage

### Compile the policy
```bash
pml2selinux compile -m model.conf -p policy.csv -o output
```

### Validate the policy
```bash
pml2selinux validate -m model.conf -p policy.csv
```

### Analyze the policy
```bash
pml2selinux analyze -m model.conf -p policy.csv
```

### Install the generated policy
```bash
cd output
checkmodule -M -m -o myapp.mod myapp.te
semodule_package -o myapp.pp -m myapp.mod -fc myapp.fc
sudo semodule -i myapp.pp
```

## Documentation

For more information, see the [PML to SELinux documentation](https://github.com/cici0602/pml-to-selinux).
