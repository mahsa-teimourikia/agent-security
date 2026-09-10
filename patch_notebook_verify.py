import json
from pathlib import Path

path = Path('curriculum/intermediate/01-identity-propagation/01_identity_propagation.ipynb')
nb = json.loads(path.read_text())

for cell in nb['cells']:
    if cell['cell_type'] == 'code':
        source = "".join(cell['source'])
        
        # ds.verify parameter fixes
        source = source.replace(
            "decision = ds.verify(fake_obj, 'document-service', 'storage-service', 'acme', 'alice', 'read', 'doc-secret')",
            "decision = ds.verify(fake_obj, 'document-service', 'storage-service', 'acme', 'read', 'doc-secret')"
        )
        
        source = source.replace(
            "decision = ds.verify(grant_101, 'research-agent', 'storage-service', 'acme', 'alice', 'read', 'doc-101')",
            "decision = ds.verify(grant_101, 'research-agent', 'storage-service', 'acme', 'read', 'doc-101')"
        )
        
        source = source.replace(
            "decision = ds.verify(grant_exp_res.grant, 'research-agent', 'document-service', 'acme', 'alice', 'read', 'doc-101')",
            "decision = ds.verify(grant_exp_res.grant, 'research-agent', 'document-service', 'acme', 'read', 'doc-101')"
        )

        cell['source'] = [line + '\n' for line in source.split('\n')]
        # Remove trailing newline from the last item
        if cell['source']:
            cell['source'][-1] = cell['source'][-1].rstrip('\n')

path.write_text(json.dumps(nb, indent=1))
