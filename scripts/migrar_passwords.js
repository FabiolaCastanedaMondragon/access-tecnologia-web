const mysql = require('mysql2');
const bcrypt = require('bcrypt');

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'access_tecnologia',
    port: 3307
});

db.connect(async err => {
    if (err) {
        console.error('❌ Error de conexión:', err);
        process.exit(1);
    }
    console.log('✅ Conectado a la BD. Iniciando migración...\n');

    db.query('SELECT id, email, password, password_hash FROM usuarios', async (err, results) => {
        if (err) {
            console.error('❌ Error al consultar usuarios:', err);
            process.exit(1);
        }

        let migrados = 0;
        let omitidos = 0;
        let errores = 0;

        for (const u of results) {
            if (u.password_hash && u.password_hash.trim() !== '') {
                console.log(`⏭️  Omitido: ${u.email} (ya tiene hash)`);
                omitidos++;
                continue;
            }

            try {
                const hash = await bcrypt.hash(u.password, 10);
                await new Promise((resolve, reject) => {
                    db.query(
                        'UPDATE usuarios SET password_hash = ? WHERE id = ?',
                        [hash, u.id],
                        (err) => err ? reject(err) : resolve()
                    );
                });
                console.log(`✅ Migrado: ${u.email}`);
                migrados++;
            } catch (e) {
                console.error(`❌ Error con ${u.email}:`, e.message);
                errores++;
            }
        }

        console.log('\n═══════════════════════════════════════');
        console.log(`🎉 Migración completada:`);
        console.log(`   ✅ Migrados:  ${migrados}`);
        console.log(`   ⏭️  Omitidos: ${omitidos}`);
        console.log(`   ❌ Errores:   ${errores}`);
        console.log('═══════════════════════════════════════\n');
        process.exit(0);
    });
});