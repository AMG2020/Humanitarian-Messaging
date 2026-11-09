# Publish to the project repository

Target: https://github.com/AMG2020/Humanitarian-Messaging

The repository was reachable publicly and contained only README.md when checked. This prepared package has not been pushed from the editing session because no authenticated GitHub write access was available.

## GitHub website

Extract the package and upload the contents of the Humanitarian-Messaging folder to the repository root. Replace the initial placeholder README with this package's README. Include humanmsg, web, tests, docs, evidence, paper, and the root files. The hidden .github/workflows/reproduce.yml file is optional automation; preserve it when using Git or uploading that path explicitly. Do not upload personal vaults, session files, credentials, real operational records, or local databases.

## Existing authenticated Git setup

Clone the existing repository first so its initial README commit is preserved:

```sh
git clone https://github.com/AMG2020/Humanitarian-Messaging.git
```

Copy the prepared package contents into that checkout, including the .github and .gitignore entries. Review the changes, select the desired licence and attribution, then commit and push with your authenticated Git client:

```sh
git add .
git commit -m "Add HumanMsg reference implementation and evaluated manuscript"
git push origin main
```

After publication, open docs/DEMONSTRATION.md, paper/Humanitarian_Messaging_SMARTCOM_2027_Final.docx, and evidence/benchmark-raw.csv through GitHub. Run the configured workflow or reproduce locally. A hosted workflow pass has not been asserted. Preserve the evaluated version with a tag or immutable commit; the manifest records file hashes.

If any tracked file changes, regenerate SOURCE_MANIFEST.json (excluding the manifest itself). New experimental runs overwrite evidence files and should be separately versioned from the measurements in the paper.
