
import { neo4jDriver } from "../config/neo4j.js";

export interface ImpactedComponent {
  id: string;
  name: string;
  version: string;
}

export async function findImpactedComponents(
  componentId: string,
  sbomId: string
): Promise<ImpactedComponent[]> {
  const session = neo4jDriver.session();

  try {
    const result = await session.run(
      `
      MATCH (impacted:Component)-[r:DEPENDS_ON*1..]->
            (vulnerable:Component {id: $componentId})
      WHERE ALL(rel IN r WHERE rel.sbomId = $sbomId)
      RETURN DISTINCT
        impacted.id AS id,
        impacted.name AS name,
        impacted.version AS version
      `,
      { componentId, sbomId }
    );

    return result.records.map((record) => ({
      id: record.get("id"),
      name: record.get("name"),
      version: record.get("version"),
    }));
  } finally {
    await session.close();
  }
}

export async function debugComponentGraph(
  componentId: string,
  sbomId: string
) {
  const session = neo4jDriver.session();

  try {
    const result = await session.run(
      `
      MATCH (c:Component {id: $componentId})
      OPTIONAL MATCH (c)-[r:DEPENDS_ON {sbomId: $sbomId}]-
                     (connected:Component)
      RETURN
        c.id AS componentId,
        count(r) AS relationshipCount,
        collect({
          id: connected.id,
          name: connected.name,
          direction: CASE
            WHEN startNode(r) = c THEN 'OUTGOING'
            ELSE 'INCOMING'
          END
        }) AS connectedComponents
      `,
      { componentId, sbomId }
    );

    return result.records.map((record) => ({
      componentId: record.get("componentId"),
      relationshipCount: record.get("relationshipCount").toNumber(),
      connectedComponents: record.get("connectedComponents"),
    }));
  } finally {
    await session.close();
  }
}

export async function hasDependencyRelationships(
  componentId: string,
  sbomId: string
): Promise<boolean> {
  const session = neo4jDriver.session();

  try {
    const result = await session.run(
      `
      MATCH (c:Component {id: $componentId})
      OPTIONAL MATCH (c)-[r:DEPENDS_ON {sbomId: $sbomId}]-()
      RETURN count(r) > 0 AS hasDependencies
      `,
      { componentId, sbomId }
    );

    return result.records[0].get("hasDependencies");
  } finally {
    await session.close();
  }
}
