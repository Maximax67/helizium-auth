import { MigrationInterface, QueryRunner } from 'typeorm';

export class $npmConfigMigration1771514342089 implements MigrationInterface {
  name = ' init1771514342089';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE "api_tokens" ("jti" uuid NOT NULL DEFAULT uuid_generate_v4(), "userId" bytea NOT NULL, "title" text NOT NULL, "writeAccess" boolean NOT NULL, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_eca71af51a84f814eee0c3255b6" PRIMARY KEY ("jti"))`,
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_2a2ce819bd75cc0193bfb2692b" ON "api_tokens" ("userId") `,
    );
    await queryRunner.query(
      `CREATE TABLE "users" ("id" bytea NOT NULL, "username" character varying NOT NULL, "email" character varying NOT NULL, "passwordHash" text, "isBanned" boolean NOT NULL DEFAULT false, "isDeleted" boolean NOT NULL DEFAULT false, "isMfaRequired" boolean NOT NULL DEFAULT false, "isEmailConfirmed" boolean NOT NULL DEFAULT false, "totpSecret" text, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "UQ_fe0bb3f6520ee0469504521e710" UNIQUE ("username"), CONSTRAINT "UQ_97672ac88f789774dd47f7c8be3" UNIQUE ("email"), CONSTRAINT "PK_a3ffb1c0c8416b9fc6f907b7433" PRIMARY KEY ("id"))`,
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_fe0bb3f6520ee0469504521e71" ON "users" ("username") `,
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_97672ac88f789774dd47f7c8be" ON "users" ("email") `,
    );
    await queryRunner.query(
      `ALTER TABLE "api_tokens" ADD CONSTRAINT "FK_2a2ce819bd75cc0193bfb2692bd" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "api_tokens" DROP CONSTRAINT "FK_2a2ce819bd75cc0193bfb2692bd"`,
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_97672ac88f789774dd47f7c8be"`,
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_fe0bb3f6520ee0469504521e71"`,
    );
    await queryRunner.query(`DROP TABLE "users"`);
    await queryRunner.query(
      `DROP INDEX "public"."IDX_2a2ce819bd75cc0193bfb2692b"`,
    );
    await queryRunner.query(`DROP TABLE "api_tokens"`);
  }
}
