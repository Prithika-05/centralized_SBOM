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