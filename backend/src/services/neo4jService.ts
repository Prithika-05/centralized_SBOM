import { neo4jDriver } from "../config/neo4j.js";

export async function testNeo4jConnection(): Promise<boolean> {
  const session = neo4jDriver.session();

  try {
    await session.run("RETURN 1");
    return true;
  } catch (error) {
    console.error("Neo4j connection failed:", error);
    return false;
  } finally {
    await session.close();
  }
}

export async function createTestNode(): Promise<void> {
  const session = neo4jDriver.session();

  try {
    await session.run(`
      CREATE (n:TestNode {
        name: "SBOM Demo"
      })
    `);
  } finally {
    await session.close();
  }
}