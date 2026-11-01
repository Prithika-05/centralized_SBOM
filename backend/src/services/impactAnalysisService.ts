import { neo4jDriver } from "../config/neo4j.js";

export interface ImpactedComponent {
  id: string;
  name: string;
  version: string;
}

export async function findImpactedComponents(
  componentId: string
): Promise<ImpactedComponent[]> {
  const session = neo4jDriver.session();

  try {
    const result = await session.run(
      `
      MATCH (impacted:Component)-[:DEPENDS_ON*1..]->(vulnerable:Component {id: $componentId})
      RETURN DISTINCT
        impacted.id AS id,
        impacted.name AS name,
        impacted.version AS version
      `,
      { componentId }
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


export async function debugComponentGraph(componentId: string) {
  const session = neo4jDriver.session();

  try {
    const result = await session.run(
      `
      MATCH (c:Component {id: $componentId})
      OPTIONAL MATCH (c)-[r:DEPENDS_ON]-(connected:Component)
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
      { componentId }
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
