import { neo4jDriver } from "../config/neo4j.js";
import { NormalizedSBOM } from "../modules/sbom/normalizer.js";

export async function storeSBOM(
  sbom: NormalizedSBOM
): Promise<void> {
  const session = neo4jDriver.session();

  try {
    await session.executeWrite(async (tx) => {
      const result = await tx.run(
        `
        CREATE (s:SBOM {
          format: $format
        })
        RETURN elementId(s) AS sbomId
        `,
        {
          format: sbom.format,
        }
      );

      const sbomId = result.records[0].get("sbomId");

      // Create component nodes
      for (const component of sbom.components) {
        await tx.run(
          `
          MATCH (s:SBOM)
          WHERE elementId(s) = $sbomId

          CREATE (c:Component {
            id: $id,
            name: $name,
            version: $version,
            supplier: $supplier,
            packageId: $packageId,
            ecosystem: $ecosystem,
            licenses: $licenses,
            hashes: $hashes
          })

          CREATE (s)-[:CONTAINS]->(c)
          `,
          {
            sbomId,
            id: component.id,
            name: component.name,
            version: component.version,
            supplier: component.supplier ?? null,
            packageId: component.packageId ?? null,
            ecosystem: component.ecosystem ?? null,
            licenses: component.licenses,
            hashes: component.hashes,
          }
        );
      }

      // Create dependency relationships
      for (const component of sbom.components) {
        for (const dependency of component.dependencies) {
          await tx.run(
            `
            MATCH (source:Component {id: $sourceId})
            MATCH (target:Component {id: $targetId})

            CREATE (source)-[:DEPENDS_ON]->(target)
            `,
            {
              sourceId: component.id,
              targetId: dependency,
            }
          );
        }
      }
    });
  } finally {
    await session.close();
  }
}