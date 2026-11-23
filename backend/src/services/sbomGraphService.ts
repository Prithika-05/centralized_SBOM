import { neo4jDriver } from "../config/neo4j.js";
import { NormalizedSBOM } from "../modules/sbom/normalizer.js";

export async function storeSBOM(
  sbom: NormalizedSBOM
  ): Promise<string> {
  const session = neo4jDriver.session();

  try {
    const sbomId = await session.executeWrite(async (tx) => {
      const result = await tx.run(
        `
        CREATE (s:SBOM {
          format: $format,
          validated: true
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

          MERGE (c:Component {id: $id})
          SET
            c.name = $name,
            c.version = $version,
            c.supplier = $supplier,
            c.packageId = $packageId,
            c.ecosystem = $ecosystem,
            c.licenses = $licenses,
            c.hashes = $hashes

          MERGE (s)-[:CONTAINS]->(c)
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

      // Create SBOM-specific dependency relationships
      for (const component of sbom.components) {
        for (const dependency of component.dependencies) {
          await tx.run(
            `
            MATCH (source:Component {id: $sourceId})
            MATCH (target:Component {id: $targetId})

            MERGE (source)-[r:DEPENDS_ON {sbomId: $sbomId}]->(target)
            `,
            {
              sbomId,
              sourceId: component.id,
              targetId: dependency,
            }
          );
        }
      }
      return sbomId;
    });
    return sbomId;
  } finally {
    await session.close();
  }
  
}


export async function hasValidatedSBOM(
  componentId: string,
  sbomId: string
): Promise<boolean> {
  const session = neo4jDriver.session();

  try {
    const result = await session.executeRead(async (tx) => {
      return tx.run(
        `
        MATCH (s:SBOM)-[:CONTAINS]->(c:Component {id: $componentId})
        WHERE elementId(s) = $sbomId
          AND s.validated = true
        RETURN count(s) > 0 AS validated
        `,
        { componentId, sbomId }
      );
    });

    return result.records[0].get("validated");
  } finally {
    await session.close();
  }
}


export async function getComponentMetadata(
  componentId: string,
  sbomId: string
): Promise<{
  name: string | null;
  version: string | null;
  supplier: string | null;
} | null> {
  const session = neo4jDriver.session();

  try {
    const result = await session.executeRead(async (tx) => {
      return tx.run(
        `
        MATCH (s:SBOM)-[:CONTAINS]->(c:Component {id: $componentId})
        WHERE elementId(s) = $sbomId
        RETURN
          c.name AS name,
          c.version AS version,
          c.supplier AS supplier
        LIMIT 1
        `,
        { componentId, sbomId }
      );
    });

    if (result.records.length === 0) {
      return null;
    }

    const record = result.records[0];

    return {
      name: record.get("name") ?? null,
      version: record.get("version") ?? null,
      supplier: record.get("supplier") ?? null,
    };
  } finally {
    await session.close();
  }
}
