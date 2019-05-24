package com.chv.rpps;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@RestController
public class RppsController 
{

	@Value("${jwt.expirationtime}")
    long EXPIRATIONTIME;
    @Value("${jwt.secret}")
    String SECRET;
    
    @Autowired
    JdbcTemplate jdbcTemplate;
    
    //logger 
    private static final Logger log = LoggerFactory.getLogger(RppsController.class);

/***************************************
 * Verification de la validite du Jeton
 * @param jeton
 * @return
 ***************************************/
    public boolean getValiditeDuJeton(String jeton) {
        Date expiration=null;
    if (jeton != null) 
    {
      // parser le jeton et verifier la date d'expiration.
      expiration = Jwts.parser()
          .setSigningKey(SECRET)
          .parseClaimsJws(jeton)
          .getBody()
          .getExpiration();
    }
    
    String USER=Jwts.parser().setSigningKey(SECRET).parseClaimsJws(jeton).getBody().getSubject();
    log.info("JWT : "+USER);
    
    //si le jeton est encore valide
    return expiration.getTime()>System.currentTimeMillis();
  }

/********************************************
 * Demande de Jeton par user
 * @param identite
 * @return
 ********************************************/
    @RequestMapping(value="/rpps/login", method = RequestMethod.POST)
    public Jeton connect(@RequestBody Identite identite)
    {
        boolean connexionOK=true;
        Jeton logDTO=new Jeton();
        String login=identite.getIdentite();
        String password=identite.getPassword();
        log.warn(login);
        log.warn(password);
        
        //verifier existance dans la base de données
        if (queryLoginDB(identite)==0)
        {
        	connexionOK=true;
        }
        else
        {
        	connexionOK=false;
        }
        
        
        if (connexionOK)
        {
          //construire le Jeton JWT
          String JWT = Jwts.builder()
      .setSubject(login)
      .setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
      .signWith(SignatureAlgorithm.HS256, SECRET)
      .compact();
          logDTO.setJeton(JWT);
        }
        else
        {
          logDTO.setJeton("NOT AUTORIZED");
        }
        //reponse JSon
        return logDTO;
    }

/******************************************
 * Query DB Utilisateurs
 * @param identite
 * @return
 ******************************************/
private int queryLoginDB(Identite identite) 
{
	int reponse=-1;
	String DBpassword=null;
	String SQL="select password from Utilisateurs where login='"+identite.getIdentite()+"' AND autorisation=1";
	try {
	jdbcTemplate.queryForList(SQL);
	Map<String,Object> rows =jdbcTemplate.queryForMap(SQL);
    DBpassword=rows.get("password").toString();
	} catch (DataAccessException er) {return reponse;}
    
    reponse=identite.getPassword().compareTo(DBpassword);
    
	return reponse;
}

/***************************************************
 * Retourner toutes les données
 * @param jeton
 * @return
 ***************************************************/
@RequestMapping(value="/rpps/getAll/{limit}",method = RequestMethod.GET)
private ResponseEntity getAll(@RequestHeader(value="Authorization") String jeton,@PathVariable("limit") String limit)
{
 
	List<RppsL> rpps=new ArrayList<>();
	
    String BEARER="Bearer";
    if(jeton.startsWith(BEARER)) {jeton = jeton.substring(BEARER.length()+1);}
    
    log.info(jeton);
    
    if (getValiditeDuJeton(jeton)==false)
    {
        return new ResponseEntity("Votre jeton est incorrect",HttpStatus.FORBIDDEN);
    }
  
    //requeter la base pour obtenir toutes les données utiles
    String sql="SELECT * FROM `rpps`.`rpps` limit "+limit;        
    
    List<Map<String,Object>> rows =jdbcTemplate.queryForList(sql);
    rows.forEach((row) -> {
        RppsL p=new RppsL();
        p.setIdentifiant_PP(row.get("identifiant_PP").toString());
        p.setNom_d_exercice(row.get("Nom_d_exercice").toString());
        p.setPrenom_d_exercice(row.get("Prenom_d_exercice").toString());
        p.setLibelle_commune(row.get("Libelle_commune").toString());
       
        rpps.add(p);
      });
    
    //retourne une liste de valeur => normalement un seul objet.
     return new ResponseEntity(rpps,HttpStatus.OK);
}

/***************************************************
 * Retourner les données sur le RPPS Num XXXXXX
 * @param jeton
 * @return
 ***************************************************/
@RequestMapping(value="/rpps/get/{NUMRPPS}",method = RequestMethod.GET)
private ResponseEntity get(@RequestHeader(value="Authorization") String jeton, @PathVariable("NUMRPPS") String numrpps)
{
 
	List<Rpps> rpps=new ArrayList<>();
	
    String BEARER="Bearer";
    if(jeton.startsWith(BEARER)) {jeton = jeton.substring(BEARER.length()+1);}
    
    log.info(jeton);
    
    if (getValiditeDuJeton(jeton)==false)
    {
        return new ResponseEntity("Votre jeton est incorrect",HttpStatus.FORBIDDEN);
    }
  
    //requeter la base pour obtenir toutes les données utiles
    String sql="SELECT * FROM `rpps`.`rpps` WHERE Identifiant_PP='"+numrpps+"'";        
    
    List<Map<String,Object>> rows =jdbcTemplate.queryForList(sql);
    rows.forEach((row) -> {
        Rpps p=new Rpps();
        p.setIdentifiant_PP(row.get("Identifiant_PP").toString());
        p.setNom_d_exercice(row.get("Nom_d_exercice").toString());
        p.setPrenom_d_exercice(row.get("Prenom_d_exercice").toString());
        p.setAdresse_e_mail(row.get("Adresse_e_mail").toString());
        p.setCode_postal(row.get("Code_postal").toString());
        p.setLibelle_profession(row.get("Libelle_profession").toString());
        p.setLibelle_savoir_faire(row.get("Libelle_savoir_faire").toString());
        p.setLibelle_type_de_voie(row.get("Libelle_type_de_voie").toString());
        p.setLibelle_Voie(row.get("Libelle_Voie").toString());
        p.setNumero_FINESS_site(row.get("Numero_FINESS_site").toString());
        p.setNumero_SIREN_site(row.get("Numero_SIREN_site").toString());
        p.setNumero_SIRET_site(row.get("Numero_SIRET_site").toString());
        p.setNumero_Voie(row.get("Numero_Voie").toString());
        p.setRaison_sociale_site(row.get("Raison_sociale_site").toString());
        p.setTelephone(row.get("Telephone").toString());
        p.setLibelle_commune(row.get("Libelle_commune").toString());
        rpps.add(p);
      });
    
    //retourne une liste de valeur => normalement un seul objet.
     return new ResponseEntity(rpps,HttpStatus.OK);
}


/***************************************************
 * Retourner les données sur le RPPS Num XXXXXX
 * @param jeton
 * @return
 ***************************************************/
@RequestMapping(value="/rpps/searchNV",method = RequestMethod.POST)
private ResponseEntity searchNV(@RequestHeader(value="Authorization") String jeton, @RequestBody CPLNV cplNV)
{
 
	List<Rpps> rpps=new ArrayList<>();
	
    String BEARER="Bearer";
    if(jeton.startsWith(BEARER)) {jeton = jeton.substring(BEARER.length()+1);}
    
    log.info(jeton);
    
    if (getValiditeDuJeton(jeton)==false)
    {
        return new ResponseEntity("Votre jeton est incorrect",HttpStatus.FORBIDDEN);
    }
  
    //requeter la base pour obtenir toutes les données utiles
    String sql="SELECT * FROM `rpps`.`rpps` WHERE Nom_d_exercice='"+cplNV.getNom()+"' AND Libelle_commune='"+cplNV.getVille()+"'";        
    
    List<Map<String,Object>> rows =jdbcTemplate.queryForList(sql);
    rows.forEach((row) -> {
        Rpps p=new Rpps();
        p.setIdentifiant_PP(row.get("Identifiant_PP").toString());
        p.setNom_d_exercice(row.get("Nom_d_exercice").toString());
        p.setPrenom_d_exercice(row.get("Prenom_d_exercice").toString());
        p.setAdresse_e_mail(row.get("Adresse_e_mail").toString());
        p.setCode_postal(row.get("Code_postal").toString());
        p.setLibelle_profession(row.get("Libelle_profession").toString());
        p.setLibelle_savoir_faire(row.get("Libelle_savoir_faire").toString());
        p.setLibelle_type_de_voie(row.get("Libelle_type_de_voie").toString());
        p.setLibelle_Voie(row.get("Libelle_Voie").toString());
        p.setNumero_FINESS_site(row.get("Numero_FINESS_site").toString());
        p.setNumero_SIREN_site(row.get("Numero_SIREN_site").toString());
        p.setNumero_SIRET_site(row.get("Numero_SIRET_site").toString());
        p.setNumero_Voie(row.get("Numero_Voie").toString());
        p.setRaison_sociale_site(row.get("Raison_sociale_site").toString());
        p.setTelephone(row.get("Telephone").toString());
        p.setLibelle_commune(row.get("Libelle_commune").toString());
        rpps.add(p);
      });
    
    //retourne une liste de valeur => normalement un seul objet.
     return new ResponseEntity(rpps,HttpStatus.OK);
}


/***************************************************
 * Supprime les données sur le RPPS Num XXXXXX
 * @param jeton
 * @return
 ***************************************************/
@RequestMapping(value="/rpps/delete/{NUMRPPS}",method = RequestMethod.DELETE)
private ResponseEntity delete(@RequestHeader(value="Authorization") String jeton, @PathVariable("NUMRPPS") String numrpps)
{
	
    String BEARER="Bearer";
    if(jeton.startsWith(BEARER)) {jeton = jeton.substring(BEARER.length()+1);}
    
    log.info(jeton);
    
    if (getValiditeDuJeton(jeton)==false)
    {
        return new ResponseEntity("Votre jeton est incorrect",HttpStatus.FORBIDDEN);
    }
  
    //requeter la base pour obtenir toutes les données utiles
    String sql="DELETE FROM `rpps`.`rpps` WHERE Identifiant_PP='"+numrpps+"'";        
    
    int numberLine= jdbcTemplate.update(sql);
    
    //retourne une liste de valeur => normalement un seul objet.
     return new ResponseEntity(numrpps+ " deleted "+ numberLine+" lines",HttpStatus.OK);
}


/***************************************************
 * Inserer nouvelles données
 * @return
 ***************************************************/
@RequestMapping(value="/rpps/insert",method = RequestMethod.POST)
private ResponseEntity insert(@RequestHeader(value="Authorization") String jeton, @RequestBody Rpps rppsB)
{
 
    String BEARER="Bearer";
    if(jeton.startsWith(BEARER)) {jeton = jeton.substring(BEARER.length()+1);}
    
    log.info(jeton);
    
    if (getValiditeDuJeton(jeton)==false)
    {
        return new ResponseEntity("Votre jeton est incorrect",HttpStatus.FORBIDDEN);
    }
  
    //requeter la base pour obtenir toutes les données utiles
    String sql="INSERT INTO `rpps` (`Identifiant_PP`, `Nom_d_exercice`, `Prenom_d_exercice`, `Libelle_profession`, `Libelle_savoir_faire`, `Numero_SIRET_site`, `Numero_SIREN_site`, `Numero_FINESS_site`, `Raison_sociale_site`, `Numero_Voie`, `Libelle_type_de_voie`, `Libelle_Voie`, `Code_postal`, `Libelle_commune`, `Telephone`, `Adresse_e_mail`) " + 
    		"VALUES ('"+rppsB.getIdentifiant_PP().toString()+"', '"+rppsB.getNom_d_exercice().toString()+"', '"+rppsB.getPrenom_d_exercice().toString()+"', '"+rppsB.getLibelle_profession().toString()+"', '"+rppsB.getLibelle_savoir_faire().toString()+"', '"+rppsB.getNumero_SIRET_site().toString()+"', '"+rppsB.getNumero_SIREN_site().toString()+"', '"+rppsB.getNumero_FINESS_site().toString()+"', '"+rppsB.getRaison_sociale_site().toString()+"', '"+rppsB.getNumero_Voie().toString()+"', '"+rppsB.getLibelle_type_de_voie().toString()+"', '"+rppsB.getLibelle_Voie().toString()+"', '"+rppsB.getCode_postal().toString()+"', '"+rppsB.getLibelle_commune().toString()+"', '"+rppsB.getTelephone().toString()+"', '"+rppsB.getAdresse_e_mail().toString()+"')";        
    
    int numberLine= jdbcTemplate.update(sql);
    
    //retourne une liste de valeur => normalement un seul objet.
     return new ResponseEntity(" insert "+ numberLine+" lines",HttpStatus.OK);
}

/***************************************************
 * Inserer nouvelles données
 * @return
 ***************************************************/
@RequestMapping(value="/rpps/update",method = RequestMethod.POST)
private ResponseEntity update(@RequestHeader(value="Authorization") String jeton, @RequestBody Rpps rppsB)
{
 
    String BEARER="Bearer";
    if(jeton.startsWith(BEARER)) {jeton = jeton.substring(BEARER.length()+1);}
    
    log.info(jeton);
    
    if (getValiditeDuJeton(jeton)==false)
    {
        return new ResponseEntity("Votre jeton est incorrect",HttpStatus.FORBIDDEN);
    }
  
    //requeter la base pour obtenir toutes les données utiles
    String sql="UPDATE `rpps`.`rpps` SET `Nom_d_exercice`='"+rppsB.getNom_d_exercice().toString()+"', `Prenom_d_exercice`='"+rppsB.getPrenom_d_exercice().toString()+"', " + 
    		"`Libelle_profession`='"+rppsB.getLibelle_profession().toString()+"', `Libelle_savoir_faire`='"+rppsB.getLibelle_savoir_faire().toString()+"', `Numero_SIRET_site`='"+rppsB.getNumero_SIRET_site().toString()+"', " + 
    		"`Numero_SIREN_site`='"+rppsB.getNumero_SIREN_site().toString()+"', `Numero_FINESS_site`='"+rppsB.getNumero_FINESS_site().toString()+"', " + 
    		"`Raison_sociale_site`='"+rppsB.getRaison_sociale_site().toString()+"', `Numero_Voie`='"+rppsB.getNumero_Voie().toString()+"', " + 
    		"`Libelle_type_de_voie`='"+rppsB.getLibelle_type_de_voie().toString()+"', `Libelle_Voie`='"+rppsB.getLibelle_Voie().toString()+"', `Code_postal`='"+rppsB.getCode_postal().toString()+"', " + 
    		"`Libelle_commune`='"+rppsB.getLibelle_commune().toString()+"', `Telephone`='"+rppsB.getTelephone().toString()+"', `Adresse_e_mail`='"+rppsB.getAdresse_e_mail().toString()+"' " + 
    		"WHERE `Identifiant_PP`='"+rppsB.getIdentifiant_PP().toString()+"'";        
    
    int numberLine= jdbcTemplate.update(sql);
    
    //retourne une liste de valeur => normalement un seul objet.
     return new ResponseEntity(" insert "+ numberLine+" lines",HttpStatus.OK);
}

}
